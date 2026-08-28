/* ============================== DECODE ==============================
   Turning pasted text into something checkable. Everything here is pure:
   no network, no storage, no side effects. That is not a style preference,
   it is the entire promise of the tool. */

function b64urlToBytes(s) {
  let t = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (t.length % 4) t += '=';
  let bin;
  // atob throws on anything that is not base64, and this function is handed
  // whatever was in the paste box. Failing softly is the whole job here.
  try { bin = atob(t); } catch (e) { throw new Error('not valid base64'); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToText(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function b64urlToText(s) {
  return bytesToText(b64urlToBytes(s));
}

/* Base64 that is NOT url-safe still needs decoding: SAML travels as plain
   base64, and half the tokens people paste have been through a system that
   re-encoded them. Accept both rather than being right and unhelpful. */
function b64ToText(s) {
  return b64urlToText(s);
}

function tryJson(text) {
  try { return { ok: true, value: JSON.parse(text) }; }
  catch (e) { return { ok: false, error: e.message }; }
}

/* ------------------------------ JWT ------------------------------ */
function decodeJwt(raw) {
  const parts = String(raw).trim().split('.');
  const out = { parts: parts.length, raw: String(raw).trim() };
  if (parts.length < 2) return { error: 'not enough segments' };
  if (parts.length === 4 || parts.length > 5) {
    // Previously a four-segment paste was decoded as a JWS and the fourth
    // segment silently discarded, which reported findings about a token that
    // did not exist. Refuse instead, and say why.
    return { error: parts.length + ' segments: a signed JWT has three and an encrypted one has ' +
                    'five. Check whether two values were pasted together, or a stray dot got in.' };
  }

  let headerText;
  try { headerText = b64urlToText(parts[0]); }
  catch (e) { return { error: 'the header segment is not base64url' }; }
  const h = tryJson(headerText);
  if (!h.ok) return { error: 'header is not JSON: ' + h.error };
  out.header = h.value;

  // A JWE has five segments and an encrypted payload; there is nothing to
  // decode without the key, but the header still says plenty.
  if (parts.length === 5) {
    out.kind = 'jwe';
    out.encrypted = true;
    out.signature = '';
    out.payloadRaw = parts[1];
    return out;
  }

  let payloadText;
  try { payloadText = b64urlToText(parts[1]); }
  catch (e) { return { error: 'the payload segment is not base64url', header: h.value }; }
  const p = tryJson(payloadText);
  if (!p.ok) return { error: 'payload is not JSON: ' + p.error, header: h.value };
  out.kind = 'jws';
  out.payload = p.value;
  out.signature = parts[2] || '';
  try { out.signatureBytes = out.signature ? b64urlToBytes(out.signature).length : 0; }
  catch (e) { out.signatureBytes = 0; }
  out.segments = parts;
  return out;
}

/* ------------------------------ XML ------------------------------ */
function decodeXml(raw) {
  let text = String(raw).trim();

  // SAML over HTTP-POST arrives base64-encoded, and over HTTP-Redirect it is
  // additionally raw-DEFLATE compressed. The browser ships an inflater
  // (DecompressionStream), so hand the bytes back for the async path to
  // inflate rather than turning the paste away. A percent-encoded value,
  // which is what a copy out of a form body or a HAR looks like, is unwrapped
  // first.
  if (!/^\s*</.test(text)) {
    let candidate = text.replace(/\s+/g, '');
    if (/%[0-9a-fA-F]{2}/.test(candidate)) {
      try { candidate = decodeURIComponent(candidate); } catch (e) { /* leave as pasted */ }
    }
    if (/^[A-Za-z0-9+/=_-]+$/.test(candidate)) {
      let bytes;
      try { bytes = b64urlToBytes(candidate); }
      catch (e) { return { error: 'looks like base64 but will not decode: ' + e.message }; }
      const decoded = bytesToText(bytes);
      if (/^\s*</.test(decoded)) {
        text = decoded;
      } else if (/[\x00-\x08\x0e-\x1f]/.test(decoded)) {
        return { deflate: bytes };
      } else {
        return { error: 'decoded, but the result is not XML' };
      }
    }
  }

  const doc = new DOMParser().parseFromString(text, 'application/xml');
  const errs = doc.getElementsByTagName('parsererror');
  if (errs && errs.length) {
    return { error: 'XML will not parse: ' + String(errs[0].textContent).slice(0, 200) };
  }
  if (!doc.documentElement) return { error: 'XML will not parse: no root element' };
  return { doc, text };
}

/* Prefix-agnostic lookup: providers disagree about prefixes, so elements are
   matched on localName. That is deliberately loose, and the SAML checks close
   the gap by verifying the namespace of the elements that matter (Assertion,
   Signature) explicitly, because a look-alike element in a foreign namespace
   is itself a finding rather than something to silently accept. */
function els(node, localName) {
  if (!node) return [];
  const all = node.getElementsByTagName('*');
  const out = [];
  for (let i = 0; i < all.length; i++) {
    if (all[i].localName === localName) out.push(all[i]);
  }
  if (node.localName === localName) out.unshift(node);
  return out;
}

function el(node, localName) {
  return els(node, localName)[0] || null;
}

function attr(node, name) {
  return node && node.getAttribute ? node.getAttribute(name) : null;
}

/* ------------------------------ certificates ------------------------------ */
/* Just enough DER walking to read notBefore and notAfter out of an X.509
   certificate. A full ASN.1 parser is not needed to answer the only question
   anyone actually has, which is whether the thing has expired. */
function certValidity(b64) {
  try {
    const bytes = b64urlToBytes(b64.replace(/\s+/g, ''));
    const times = [];
    for (let i = 0; i < bytes.length - 2; i++) {
      const tag = bytes[i], len = bytes[i + 1];
      // UTCTime is 0x17 (len 13, YYMMDDhhmmssZ), GeneralizedTime is 0x18 (len 15)
      if ((tag === 0x17 && len === 13) || (tag === 0x18 && len === 15)) {
        const s = bytesToText(bytes.slice(i + 2, i + 2 + len));
        if (!/^\d{12,14}Z$/.test(s)) continue;
        let y, rest;
        if (tag === 0x17) {
          const yy = parseInt(s.slice(0, 2), 10);
          y = yy >= 50 ? 1900 + yy : 2000 + yy;
          rest = s.slice(2);
        } else {
          y = parseInt(s.slice(0, 4), 10);
          rest = s.slice(4);
        }
        const d = new Date(Date.UTC(y, +rest.slice(0, 2) - 1, +rest.slice(2, 4),
                                    +rest.slice(4, 6), +rest.slice(6, 8), +rest.slice(8, 10)));
        if (!isNaN(d)) times.push(d);
        if (times.length === 2) break;
      }
    }
    if (times.length === 2) return { notBefore: times[0], notAfter: times[1] };
  } catch (e) { /* an unreadable certificate is reported by the caller */ }
  return null;
}

/* Key size from a JWK modulus, which is what decides whether an RSA key is
   too small to still be trusted. Returns null when the modulus does not
   decode, and the CALLER reports that: a swallowed decode error here once
   meant a malformed key produced no finding at all. */
function rsaBits(n) {
  try {
    const bytes = b64urlToBytes(n);
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) i++;   // strip leading zero padding
    return (bytes.length - i) * 8;
  } catch (e) { return null; }
}

/* Raw DEFLATE, the redirect binding's compression, inflated with the
   decompressor the browser ships. No library, no network: bytes in this tab,
   bytes out in this tab. */
function inflateRaw(bytes) {
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  return new Response(stream).arrayBuffer().then(buf => bytesToText(new Uint8Array(buf)));
}
