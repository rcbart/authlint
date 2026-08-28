/* ============================== AUTHORIZATION REQUEST CHECKS ==============================
   Paste the URL out of the address bar, or out of a HAR file, or out of the
   network tab. Most of what is wrong with an OAuth deployment is visible in
   this one line, and almost nobody reads it. */

function parseAuthz(text, asQuery) {
  const out = { params: {}, dups: {}, base: '', fragment: false, scheme: '' };
  const put = (k, v) => {
    if (k in out.params && out.params[k] !== v) {
      (out.dups[k] = out.dups[k] || [out.params[k]]).push(v);
    }
    out.params[k] = v;
  };
  let s = String(text).trim();

  if (asQuery) {
    for (const [k, v] of new URLSearchParams(s.replace(/^[?&]/, ''))) put(k, v);
    return out;
  }

  let u;
  try { u = new URL(s); } catch (e) { return { error: 'not a URL: ' + e.message }; }
  out.base = u.origin + u.pathname;
  out.scheme = u.protocol.replace(':', '');
  for (const [k, v] of u.searchParams) put(k, v);
  if (u.hash && u.hash.length > 1) {
    out.fragment = true;
    for (const [k, v] of new URLSearchParams(u.hash.slice(1))) {
      put(k, v);
      out.fragmentParams = out.fragmentParams || {};
      out.fragmentParams[k] = v;
    }
  }
  return out;
}

function checkAuthz(a, now) {
  const f = [];
  const p = a.params || {};
  const rt = String(p.response_type || '').toLowerCase().trim();

  /* A redirect carrying results, rather than a request. Different checks matter. */
  const isCallback = !!(p.code || p.access_token || p.id_token || p.error);

  /* ---------------- parameter pollution, before anything trusts p ---------------- */
  for (const k of Object.keys(a.dups || {})) {
    const vals = a.dups[k];
    f.push(F('critical', 'Parameter "' + k + '" appears ' + vals.length + ' times with different values',
      'OAuth forbids repeating a parameter, because implementations disagree about which copy ' +
      'wins: first, last, or concatenated. An attacker exploits exactly that disagreement, and ' +
      'the copy your provider honoured may not be the copy you are reading. Values seen: ' +
      vals.map(v => String(v).slice(0, 80)).join('  |  '),
      'Reject requests with duplicated parameters.', 'RFC 6749 §3.1'));
  }

  if (a.scheme === 'http' && !/^https?:\/\/(localhost|127\.0\.0\.1)/.test(a.base)) {
    f.push(F('critical', 'Plaintext http',
      'Everything in this URL is readable and rewritable in transit, including the code and the ' +
      'redirect target.', 'Use https everywhere except loopback during development.', 'RFC 9700 §2.1'));
  }

  if (p.client_secret) {
    f.push(F('critical', 'client_secret is in the URL',
      'This is a front-channel request. The secret is now in the browser address bar, the history, ' +
      'the referrer header and every proxy log between here and the provider. Treat it as public.',
      'Rotate the secret. Client authentication belongs on the back-channel token request only.',
      'RFC 6749 §2.3.1'));
  }

  if (a.fragmentParams && (a.fragmentParams.access_token || a.fragmentParams.id_token)) {
    f.push(F('warn', 'Tokens returned in the URL fragment',
      'Fragments reach browser history and anything that reads location. This is the implicit flow ' +
      'or a hybrid variant of it.',
      'Move to the authorization code flow with PKCE.', 'RFC 9700 §2.1.2'));
  }

  if (!isCallback) {
    if (!rt) {
      f.push(F('warn', 'No response_type', 'Not a complete authorization request.', '', 'RFC 6749 §4.1.1'));
    } else if (rt === 'code') {
      f.push(F('ok', 'Authorization code flow', ''));
    } else if (/token/.test(rt)) {
      f.push(F('critical', 'response_type=' + rt + ' returns tokens through the browser',
        'The implicit and hybrid flows hand tokens to the front channel, where they land in history ' +
        'and referrer headers. Both have been advised against for years.',
        'Use response_type=code with PKCE.', 'RFC 9700 §2.1.2'));
    }

    if (!p.code_challenge) {
      f.push(F('critical', 'No PKCE',
        'Without a challenge, anyone who intercepts the authorization code can redeem it. That is ' +
        'the attack PKCE was written to stop, and it applies to confidential clients too.',
        'Send code_challenge with code_challenge_method=S256.', 'RFC 9700 §2.1.1'));
    } else if (String(p.code_challenge_method || 'plain').toLowerCase() !== 's256') {
      f.push(F('warn', 'code_challenge_method is ' + (p.code_challenge_method || 'plain (the default)'),
        'The plain method puts the verifier in the request in the clear, so an attacker who can read ' +
        'the request can also complete the exchange.',
        'Use S256.', 'RFC 7636 §7.2'));
    } else {
      f.push(F('ok', 'PKCE with S256', ''));
    }

    /* state and CSRF. PKCE covers CSRF when the client completes the code
       exchange and verifies it, so the two absences mean different things. */
    if (!p.state) {
      if (!p.code_challenge) {
        f.push(F('warn', 'No state and no PKCE',
          'Nothing binds the callback to the browser session that started it, which is what makes ' +
          'login CSRF possible.',
          'Send PKCE (which covers CSRF when the exchange is verified) or an unguessable state ' +
          'checked on return.', 'RFC 9700 §2.1, RFC 6749 §10.12'));
      } else {
        f.push(F('note', 'No state parameter',
          'With PKCE present and verified at the token exchange, CSRF is covered and state is ' +
          'application routing rather than a required security parameter. It is still the usual ' +
          'place to carry "where do I send the user back to".',
          '', 'RFC 9700 §2.1'));
      }
    } else if (String(p.state).length < 16 && !p.code_challenge) {
      f.push(F('warn', 'state is only ' + String(p.state).length + ' characters and is doing CSRF duty',
        'Without PKCE, state is the CSRF defense, and a short value is guessable.',
        'Use at least 128 bits of randomness, or add PKCE.', 'RFC 6749 §10.12'));
    } else {
      f.push(F('ok', 'state present', ''));
    }

    if (/id_token/.test(rt) && !p.nonce) {
      f.push(F('critical', 'ID token requested with no nonce',
        'The nonce is what ties the returned ID token to this request. Without it, a token captured ' +
        'elsewhere can be replayed into this session.',
        'Send a nonce and check it in the returned token.', 'OIDC Core §3.1.2.1'));
    }

    if (!p.scope) {
      f.push(F('note', 'No scope requested', 'The provider will apply its default, whatever that is.'));
    } else {
      const scopes = String(p.scope).split(/[\s+]+/).filter(Boolean);
      if (!scopes.includes('openid') && (p.nonce || /id_token/.test(rt))) {
        f.push(F('warn', 'Looks like OpenID Connect but scope is missing "openid"',
          'Without it this is plain OAuth and you will not get an ID token, whatever else you asked for.',
          '', 'OIDC Core §3.1.2.1'));
      }
      if (scopes.some(s => /^(.*\.)?(\*|all|full_access|admin)$/i.test(s))) {
        f.push(F('warn', 'Very broad scope requested: ' + scopes.join(' '),
          'The token you get back is as powerful as the scope you asked for, and it will be logged ' +
          'somewhere.', 'Ask for the narrowest scope the feature needs.'));
      }
      if (scopes.length > 12) {
        f.push(F('note', scopes.length + ' scopes requested',
          'Long scope lists usually mean one client is doing several unrelated jobs.'));
      }
    }
  }

  /* ---------------- redirect_uri, where a surprising amount goes wrong ---------------- */
  if (p.redirect_uri) {
    const r = String(p.redirect_uri);
    if (/[*]/.test(r)) {
      f.push(F('critical', 'redirect_uri contains a wildcard',
        'If the provider honours it, an attacker picks the destination the code is delivered to.',
        'Register exact URIs. No wildcards, no prefixes.', 'RFC 9700 §2.1'));
    }
    if (/^http:/i.test(r) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(r)) {
      f.push(F('critical', 'redirect_uri is plaintext http: ' + r,
        'The code is delivered over a channel anyone on the path can read.', 'Use https.', 'RFC 9700 §2.1'));
    }
    if (/#/.test(r)) {
      f.push(F('warn', 'redirect_uri contains a fragment',
        'Fragments are not permitted in a redirect URI and providers differ on what they do with one.',
        '', 'RFC 6749 §3.1.2'));
    }
    if (/^(urn:ietf:wg:oauth:2\.0:oob|oob)$/i.test(r)) {
      f.push(F('warn', 'Out-of-band redirect (copy the code by hand)',
        'Deprecated, and the copy-paste step is exactly where users get phished.',
        'Use a loopback redirect for native applications.', 'RFC 9700 §2.1'));
    }
    /* The exact-match bypass shapes. A wildcard is the amateur version; these
       are what a real bypass attempt looks like, and a provider that matches
       loosely falls to one of them long before it falls to a "*". */
    let ru = null;
    try { ru = new URL(r); } catch (e) { /* non-URL redirect handled above */ }
    if (ru && (ru.username || ru.password)) {
      f.push(F('critical', 'redirect_uri has userinfo in the authority: ' + r,
        'Everything before the @ is credentials, not the host. A validator that matches on ' +
        '"starts with https://app.example.com" reads the wrong host, and the browser delivers ' +
        'the code to what comes after the @.',
        'Reject redirect URIs containing @.', 'RFC 9700 §4.1'));
    }
    if (/\\/.test(r)) {
      f.push(F('warn', 'redirect_uri contains a backslash',
        'Browsers treat \\ as / in URLs; many server-side parsers do not. Every disagreement ' +
        'between the validator\'s parser and the browser\'s is a bypass.',
        'Reject it.', 'RFC 9700 §4.1'));
    }
    if (/\/\.\.(\/|$)|%2e%2e/i.test(r)) {
      f.push(F('warn', 'redirect_uri contains path traversal: ' + r,
        'If the provider normalises the path after matching, the code is delivered somewhere other ' +
        'than the registered path.',
        'Match the registered URI byte for byte, after normalising exactly once.', 'RFC 9700 §4.1'));
    }
    if (ru && /[?&](url|next|redirect|return|dest|goto|continue)=(https?%3a|https?:)/i.test(ru.search)) {
      f.push(F('warn', 'redirect_uri carries a nested URL in its query: ' + ru.search.slice(0, 80),
        'A forwarding parameter inside the registered redirect target is an open redirect one hop ' +
        'later: the provider delivers the code to the right page, and that page hands it on.',
        'Do not put open redirectors inside registered redirect URIs.', 'RFC 9700 §4.11'));
    }
    if (ru && !/^https?:$/.test(ru.protocol)) {
      f.push(F('note', 'redirect_uri uses a custom scheme: ' + ru.protocol,
        'Normal for native apps, and claimable: on several platforms any app can register the same ' +
        'scheme and receive the code. Loopback or claimed https links are the stronger options.',
        '', 'RFC 8252 §8.1'));
    }
  } else if (!isCallback) {
    f.push(F('note', 'No redirect_uri in the request',
      'Legal when the client has exactly one registered URI, and a source of confusion when it does not.'));
  }

  /* ---------------- the callback side ---------------- */
  if (isCallback) {
    if (p.error) {
      f.push(F('note', 'Provider returned error=' + p.error +
        (p.error_description ? ': ' + p.error_description : ''),
        'The description is the provider\'s, not authlint\'s.'));
    }
    if (p.code) {
      f.push(F('ok', 'Authorization code returned on the front channel, as intended', ''));
      if (p.iss) {
        f.push(F('ok', 'Callback carries iss: ' + p.iss,
          'The issuer identification parameter. A client that compares this against the issuer it ' +
          'started with cannot be caught by a mix-up across providers.', '', 'RFC 9207 §2'));
      } else {
        f.push(F('note', 'Callback carries no iss parameter',
          'With more than one provider configured, a client cannot tell which issuer this code came ' +
          'from, which is the opening for mix-up attacks. Providers that support RFC 9207 return ' +
          'iss on every authorization response.',
          'If the provider advertises authorization_response_iss_parameter_supported, verify iss here.',
          'RFC 9207 §2, RFC 9700 §4.4.2.1'));
      }
    }
    if (p.access_token) {
      f.push(F('critical', 'An access token came back in the URL',
        'It is now in the browser history and in any referrer header this page emits.',
        'Switch to the code flow.', 'RFC 9700 §2.1.2'));
    }
    if (!p.state && !p.error) {
      f.push(F('warn', 'Callback carries no state',
        'Nothing to compare against what you sent. If the request used PKCE the CSRF risk is ' +
        'covered at the exchange; if it did not, this callback is unbound.', '', 'RFC 9700 §2.1'));
    }
  }

  return sortFindings(f);
}
