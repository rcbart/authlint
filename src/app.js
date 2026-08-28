/* ============================== APP ==============================
   One box in, findings out. No routing, no state to speak of, and
   deliberately no network: everything below runs on the string you pasted
   and nothing else. */

const $ = id => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function nowSeconds() { return Math.floor(Date.now() / 1000); }

/* ------------------------------ analysis ------------------------------ */

function analyze(input) {
  const now = nowSeconds();
  const d = detect(input);
  if (!d.kind) {
    return { error: d.reason || 'authlint cannot tell what this is.' };
  }
  const text = d.rewrite || input;

  // A SAML document extracted from a URL parameter: decide what the decoded
  // value is and analyze that. One level of recursion, by construction.
  if (d.kind === 'samlparam') {
    return analyze(text);
  }

  if (d.kind === 'cookie') {
    return {
      kind: /^set-cookie:/im.test(text) ? 'Set-Cookie response header' : 'Cookie request header',
      decoded: '<pre class="code">' + esc(text) + '</pre>',
      findings: checkCookie(text, now),
    };
  }

  if (d.kind === 'tokenresp') {
    const j = JSON.parse(text);
    return {
      kind: typeof j.active === 'boolean' ? 'Token introspection response' : 'Token endpoint response',
      decoded: renderJson(j),
      findings: checkTokenResponse(j, now),
      also: nestedJwts(j),
    };
  }

  if (d.kind === 'jwt') {
    const t = decodeJwt(text);
    if (t.error) return { error: t.error, kind: d.kind };
    return {
      kind: t.kind === 'jwe' ? 'Encrypted JWT (JWE)' : describeJwt(t),
      decoded: renderJwt(t),
      findings: checkJwt(t, now),
    };
  }

  if (d.kind === 'samllogout' || d.kind === 'samlreq') {
    const x = decodeXml(text);
    if (x.error) return { error: x.error };
    if (x.deflate) return { deflate: x.deflate };
    return {
      kind: d.kind === 'samlreq' ? 'SAML authentication request'
          : 'SAML logout message (' + x.doc.documentElement.localName + ')',
      decoded: renderXml(x.text),
      findings: d.kind === 'samlreq' ? checkSamlAuthnRequest(x, now) : checkSamlLogout(x, now),
    };
  }

  if (d.kind === 'jwks') {
    const j = JSON.parse(text);
    return {
      kind: 'JSON Web Key Set',
      decoded: renderJson(j),
      findings: checkJwks(j, now),
    };
  }

  if (d.kind === 'discovery') {
    const j = JSON.parse(text);
    return {
      kind: 'OpenID Connect discovery document',
      decoded: renderJson(j),
      findings: checkDiscovery(j, now),
    };
  }

  if (d.kind === 'authz') {
    const a = parseAuthz(text, d.asQuery);
    if (a.error) return { error: a.error };
    const isCallback = !!(a.params.code || a.params.access_token || a.params.id_token || a.params.error);
    return {
      kind: isCallback ? 'OAuth 2.0 redirect (callback)' : 'OAuth 2.0 authorization request',
      decoded: renderParams(a),
      findings: checkAuthz(a, now),
      also: nestedJwts(a.params),
      hashParams: a.params,
    };
  }

  const x = decodeXml(text);
  if (x.error) return { error: x.error };
  if (x.deflate) return { deflate: x.deflate };
  if (d.kind === 'samlmeta') {
    return { kind: 'SAML metadata', decoded: renderXml(x.text), findings: checkSamlMetadata(x, now) };
  }
  return {
    kind: 'SAML response',
    decoded: renderXml(x.text),
    findings: checkSamlResponse(x, now),
  };
}

/* ---------------- the one verification that needs no key ----------------
   at_hash and c_hash are the left half of a hash of the access token and the
   code, under the hash of the ID token's own alg. When a redirect carries
   both halves, the claim is checkable right here, offline: WebCrypto digests
   bytes in this tab and nothing leaves it. This is the difference between
   "authlint cannot verify without the key" and not verifying what it can. */
function verifyOidcHashes(params) {
  const results = [];
  const idt = params && params.id_token;
  if (!idt || typeof crypto === 'undefined' || !crypto.subtle) return Promise.resolve(results);
  const t = decodeJwt(idt);
  if (t.error || t.kind !== 'jws' || !t.payload) return Promise.resolve(results);
  const m = String(t.header.alg || '').match(/(256|384|512)$/);
  if (!m) return Promise.resolve(results);
  const sha = 'SHA-' + m[1];

  const jobs = [];
  for (const [claim, artifact, label, ref] of [
      ['at_hash', params.access_token, 'access token', 'OIDC Core §3.2.2.9'],
      ['c_hash', params.code, 'authorization code', 'OIDC Core §3.3.2.10']]) {
    const expected = t.payload[claim];
    if (!expected || !artifact) continue;
    jobs.push(crypto.subtle.digest(sha, new TextEncoder().encode(String(artifact))).then(buf => {
      const digest = new Uint8Array(buf);
      const half = digest.slice(0, digest.length / 2);
      let bin = '';
      for (let i = 0; i < half.length; i++) bin += String.fromCharCode(half[i]);
      const got = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      if (got === String(expected)) {
        results.push(F('ok', claim + ' verifies against the ' + label + ' in this redirect',
          'Computed here, offline: ' + sha + ' over the ' + label + ', left half, base64url. No ' +
          'key needed, nothing sent anywhere.', '', ref));
      } else {
        results.push(F('critical', claim + ' does NOT match the ' + label + ' in this redirect',
          'The ID token was issued alongside a different ' + label + ' than the one riding next ' +
          'to it. That is what token substitution looks like: someone swapped one artifact in a ' +
          'response whose other half they kept.',
          'Reject the response. If you are debugging, confirm both values came from the same ' +
          'redirect.', ref));
      }
    }).catch(() => { /* a digest that cannot run is simply not reported */ }));
  }
  return Promise.all(jobs).then(() => results);
}

/* A redirect often carries an id_token worth checking on its own. */
function nestedJwts(params) {
  const out = [];
  for (const k of ['id_token', 'access_token']) {
    const v = params[k];
    if (v && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(v)) out.push({ name: k, value: v });
  }
  return out;
}

function describeJwt(t) {
  const prof = jwtProfile(t);
  if (prof === 'dpop') return 'DPoP proof';
  if (prof === 'logout') return 'OIDC back-channel logout token';
  if (prof === 'id') return 'OpenID Connect ID token';
  if (prof === 'at') return 'OAuth 2.0 access token (JWT)';
  return 'JSON Web Token';
}

/* ------------------------------ rendering ------------------------------ */

function renderJson(o) {
  return '<pre class="code">' + esc(JSON.stringify(o, null, 2)) + '</pre>';
}

function renderJwt(t) {
  let h = '<div class="seg"><h4>Header</h4><pre class="code">' +
          esc(JSON.stringify(t.header, null, 2)) + '</pre></div>';
  if (t.kind === 'jwe') {
    h += '<div class="seg"><h4>Payload</h4><p class="dim">Encrypted. Nothing to show without the key.</p></div>';
  } else {
    h += '<div class="seg"><h4>Payload</h4><pre class="code">' +
         esc(JSON.stringify(t.payload, null, 2)) + '</pre></div>';
    const claims = timeClaims(t.payload);
    if (claims) h += '<div class="seg"><h4>Times</h4>' + claims + '</div>';
    h += '<div class="seg"><h4>Signature</h4><pre class="code">' +
         esc(t.signature || '(empty)') +
         (t.signatureBytes ? '\n\n' + t.signatureBytes + ' bytes' : '') + '</pre></div>';
  }
  return h;
}

function timeClaims(p) {
  if (!p) return '';
  const rows = [];
  for (const k of ['iat', 'nbf', 'exp', 'auth_time', 'updated_at']) {
    if (typeof p[k] !== 'number') continue;
    const ms = looksLikeMillis(p[k]) ? p[k] : p[k] * 1000;
    rows.push('<tr><td>' + k + '</td><td>' + p[k] + '</td><td>' +
      esc(new Date(ms).toISOString().replace('T', ' ').replace('.000Z', ' UTC')) + '</td></tr>');
  }
  return rows.length ? '<table class="times"><tbody>' + rows.join('') + '</tbody></table>' : '';
}

function renderParams(a) {
  const dups = a.dups || {};
  const rows = Object.keys(a.params).map(k => {
    const vals = dups[k] || [a.params[k]];
    const shown = vals.map(v => {
      const s = String(v);
      return s.length > 300 ? s.slice(0, 300) + '…' : s;
    });
    // Every copy of a duplicated parameter is displayed, because the copy the
    // provider honoured may not be the last one, and hiding the others hides
    // the attack.
    return '<tr><td>' + esc(k) + (vals.length > 1 ? ' <b>×' + vals.length + '</b>' : '') +
           '</td><td><code>' + shown.map(esc).join('</code><br><code>') + '</code></td></tr>';
  }).join('');
  return (a.base ? '<p class="dim">Endpoint: <code>' + esc(a.base) + '</code></p>' : '') +
         '<table class="params"><tbody>' + rows + '</tbody></table>';
}

function renderXml(text) {
  return '<p class="dim">Re-indented for reading. Whitespace differs from the pasted original, ' +
         'which matters if you are eyeballing byte-exact values: trust the findings, not the ' +
         'indentation.</p><pre class="code">' + esc(prettyXml(text)) + '</pre>';
}

/* Indentation only. Nothing here reorders or rewrites the document, because
   the thing being inspected has to stay the thing that was pasted. */
function prettyXml(xml) {
  const parts = String(xml).replace(/>\s*</g, '><').replace(/></g, '>\n<').split('\n');
  let depth = 0;
  return parts.map(line => {
    if (/^<\//.test(line)) depth = Math.max(0, depth - 1);
    const out = '  '.repeat(depth) + line;
    if (/^<[^!?/][^>]*[^/]>$/.test(line) && !/^<\//.test(line)) depth++;
    return out;
  }).join('\n');
}

const SEV_LABEL = { critical: 'Critical', warn: 'Warning', note: 'Note', ok: 'Pass' };

function renderFindings(list) {
  if (!list || !list.length) return '<p class="dim">No findings.</p>';
  return list.map(x =>
    '<div class="f ' + x.sev + '">' +
      '<div class="fh"><span class="sev">' + SEV_LABEL[x.sev] + '</span>' +
        '<span class="ft">' + esc(x.title) + '</span></div>' +
      (x.why ? '<p class="fw">' + esc(x.why) + '</p>' : '') +
      (x.fix ? '<p class="ff"><b>Fix</b> ' + esc(x.fix) + '</p>' : '') +
      (x.ref ? '<p class="fr">' + esc(x.ref) + '</p>' : '') +
    '</div>').join('');
}

/* Two different failures deserve two different answers. "This is a JWT and the
   payload segment is truncated" is a fix somebody can act on in seconds. "I do
   not know what this is" is a different message, and it should at least say what
   the tool does read. Both go through esc(), because every word of this is
   quoting something that was pasted. */
function renderDiagnosis(input, fallback) {
  let d = null;
  try { d = diagnose(input); } catch (e) { d = null; }

  if (!d) {
    return '<div class="diag unknown"><div class="dh">' +
      '<span class="dsev">Not recognised</span>' +
      '<span class="dt">' + esc(fallback || 'authlint cannot tell what this is.') + '</span></div>' +
      '<p class="dhint">' + esc(ACCEPTED_SENTENCE) + '</p></div>';
  }

  const malformed = d.state === 'malformed';
  const heading = malformed
    ? (d.looksLike ? 'This looks like ' + d.looksLike + ', but it seems malformed.'
                   : 'This looks like something authlint reads, but it seems malformed.')
    : (d.looksLike ? 'This looks like ' + d.looksLike + ', which authlint does not read.'
                   : 'authlint does not recognise this.');

  let h = '<div class="diag ' + (malformed ? 'malformed' : 'unknown') + '">' +
    '<div class="dh">' +
      '<span class="dsev">' + (malformed ? 'Malformed' : 'Unrecognised format') + '</span>' +
      '<span class="dt">' + esc(heading) + '</span>' +
    '</div>';
  if (d.problem) h += '<p class="dwhy">' + esc(d.problem) + '</p>';
  if (d.hint) h += '<p class="dhint">' + esc(d.hint) + '</p>';
  if (!malformed && !d.looksLike) h += '<p class="dfoot">' + esc(ACCEPTED_SENTENCE) + '</p>';
  return h + '</div>';
}

const ACCEPTED_SENTENCE =
  'authlint reads JSON Web Tokens (including DPoP proofs and JWEs), JWKS documents, OpenID ' +
  'Connect discovery documents, OAuth authorization requests and redirects, token endpoint and ' +
  'introspection responses, Set-Cookie headers, SAML responses, assertions, requests, logout ' +
  'messages and metadata. Redirect-binding SAML is inflated automatically, in the browser.';

function counts(list) {
  const c = { critical: 0, warn: 0, note: 0, ok: 0 };
  (list || []).forEach(x => { c[x.sev]++; });
  return c;
}

/* ------------------------------ wiring ------------------------------ */

async function run() {
  const input = $('in').value.trim();
  const out = $('out');
  if (!input) { out.innerHTML = ''; $('summary').innerHTML = ''; return; }

  let r;
  try { r = analyze(input); }
  catch (e) { r = { error: 'authlint fell over on this input: ' + e.message }; }

  /* Redirect-binding SAML: the bytes came back compressed, so inflate them
     with the browser's own decompressor and analyze what comes out. Async
     because DecompressionStream is, and still entirely inside this tab. */
  if (r && r.deflate) {
    try {
      const inflated = await inflateRaw(r.deflate);
      if (/^\s*</.test(inflated)) {
        r = analyze(inflated);
        if (r && !r.error) {
          r.kind = (r.kind || '') + ' (inflated from the redirect binding)';
        }
      } else {
        r = { error: 'inflated, but the result is not XML' };
      }
    } catch (e) {
      r = { error: 'looks like compressed data but will not inflate. If it came from a ' +
                   'redirect binding it may be truncated; the POST binding version also works.' };
    }
  }

  /* The key-free cryptographic checks: at_hash and c_hash, when a redirect
     carries both the ID token and the artifact it hashes. */
  if (r && !r.error && r.hashParams) {
    try {
      const extra = await verifyOidcHashes(r.hashParams);
      if (extra.length) r.findings = sortFindings((r.findings || []).concat(extra));
    } catch (e) { /* verification that cannot run is simply not reported */ }
  }

  if (r.error) {
    $('summary').innerHTML = '';
    out.innerHTML = renderDiagnosis(input, r.error);
    return;
  }

  const c = counts(r.findings);
  $('summary').innerHTML =
    '<div class="kind">' + esc(r.kind) + '</div>' +
    '<a class="jump" href="#findings">jump to findings</a>' +
    '<div class="tallies">' +
      (c.critical ? '<span class="t critical">' + c.critical + ' critical</span>' : '') +
      (c.warn ? '<span class="t warn">' + c.warn + ' warning' + (c.warn > 1 ? 's' : '') + '</span>' : '') +
      (c.note ? '<span class="t note">' + c.note + ' note' + (c.note > 1 ? 's' : '') + '</span>' : '') +
      (c.ok ? '<span class="t ok">' + c.ok + ' pass' + (c.ok > 1 ? 'es' : '') + '</span>' : '') +
    '</div>';

  /* Decoded goes first. It used to sit under the findings, which put it two
     thousand pixels down the page on a token with a lot of claims, and the
     first thing anyone wants from a paste box is to read what they pasted.
     The findings are what makes this better than a decoder; they are not what
     makes it useful in the first ten seconds. */
  let html = '<section class="decoded"><h3>Decoded</h3>' + r.decoded + '</section>';
  html += '<section class="findings" id="findings"><h3>Findings</h3>' +
          renderFindings(r.findings) + '</section>';
  if (r.also && r.also.length) {
    html += r.also.map(n => {
      const t = decodeJwt(n.value);
      if (t.error) return '';
      const nf = checkJwt(t, nowSeconds());
      return '<section class="findings nested"><h3>' + esc(n.name) + ', decoded and checked separately</h3>' +
             renderFindings(nf) + '</section>';
    }).join('');
  }
  out.innerHTML = html;
}

function loadSample(which) {
  $('in').value = SAMPLES[which] || '';
  run();
}

document.addEventListener('DOMContentLoaded', function () {
  $('in').addEventListener('input', debounce(run, 120));
  document.querySelectorAll('[data-sample]').forEach(b => {
    b.addEventListener('click', () => loadSample(b.getAttribute('data-sample')));
  });
  $('clear').addEventListener('click', () => { $('in').value = ''; run(); $('in').focus(); });
  run();
});

function debounce(fn, ms) {
  let t;
  return function () { clearTimeout(t); t = setTimeout(fn, ms); };
}
