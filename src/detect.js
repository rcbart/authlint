/* ============================== DETECT ==============================
   One box, and the tool works out what you pasted. Nobody debugging a
   federation problem at 2am wants to first tell a form what kind of artifact
   they are holding, and half the time they are not sure.

   Order matters: the cheapest and most certain shapes are tested first, and
   anything that stays ambiguous is handed to diagnose(), which explains
   rather than guesses. */

function detect(raw) {
  const text = String(raw || '').trim();
  if (!text) return { kind: null };

  // Cookie headers, either direction. The value is usually opaque; the
  // attributes are the artifact.
  if (/^(set-cookie|cookie):/im.test(text)) {
    return { kind: 'cookie' };
  }

  // A bearer header pasted whole, which people do constantly. This must be
  // tested BEFORE the bare-JWT shape below: that test strips whitespace so a
  // wrapped token still matches, which also turns "Bearer eyJ..." into
  // "BearereyJ...", a string made entirely of base64url characters. Ordered the
  // other way round, a bare Bearer paste matches as a JWT with no rewrite and
  // the prefix is carried into the decoder.
  const bearer = text.match(/^(?:Authorization:\s*)?Bearer\s+([A-Za-z0-9_.-]+)$/i);
  if (bearer) return { kind: 'jwt', rewrite: bearer[1] };

  // A JWT is three base64url segments, an encrypted one five. Four segments
  // still get routed to the decoder, which refuses them with a reason a
  // person can act on; swallowing the extra segment would be worse.
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*){1,3}$/.test(text.replace(/\s+/g, ''))) {
    return { kind: 'jwt' };
  }

  // A URL. Only an OAuth one: a URL with a query string is not automatically
  // an authorization request, and grading a search link for missing PKCE
  // helped nobody. A redirect-binding SSO URL carries the SAML document in a
  // parameter, so unwrap that first.
  if (/^https?:\/\//i.test(text) && /[?#]/.test(text)) {
    const saml = text.match(/[?&](SAMLResponse|SAMLRequest|LogoutRequest|LogoutResponse)=([^&#\s]+)/i);
    if (saml) {
      let v = saml[2];
      try { v = decodeURIComponent(v); } catch (e) { /* use as-is */ }
      return { kind: 'samlparam', rewrite: v };
    }
    if (/[?#&](response_type|client_id|redirect_uri|scope|state|code|access_token|id_token|error|code_challenge|iss|token_type)=/i.test(text)) {
      return { kind: 'authz' };
    }
    return { kind: null, reason: 'a URL with parameters, none of which are OAuth parameters. ' +
                                 'authlint reads authorization requests and redirects.' };
  }

  // JSON: which document depends on what is inside it.
  if (/^[\[{]/.test(text)) {
    try {
      const j = JSON.parse(text);
      if (j && Array.isArray(j.keys)) return { kind: 'jwks' };
      if (j && (j.issuer || j.authorization_endpoint || j.jwks_uri)) {
        return { kind: 'discovery' };
      }
      // The token endpoint's answer, or an introspection response: the two
      // most-pasted JSON artifacts in any OAuth debugging session.
      if (j && (j.access_token || j.refresh_token ||
                (j.token_type && j.expires_in != null) || j.id_token)) {
        return { kind: 'tokenresp' };
      }
      if (j && typeof j.active === 'boolean') return { kind: 'tokenresp' };
      if (j && (j.error && (j.error_description || j.error_uri))) return { kind: 'tokenresp' };
      if (j && (j.kty || j.n || j.crv)) return { kind: 'jwks' };
      return { kind: null, reason: 'JSON, but not a shape authlint knows' };
    } catch (e) {
      return { kind: null, reason: 'starts like JSON but will not parse: ' + e.message };
    }
  }

  // XML, either raw or base64. Look at the root element to tell them apart.
  // Logout messages are tested before the generic Response match, because
  // LogoutResponse IS a "*Response" and used to be graded with sign-on
  // response rules, which produced nonsense findings on it.
  const xmlish = /^\s*</.test(text) ? text : peekBase64Xml(text);
  if (xmlish) {
    if (/<[\w:]*EntityDescriptor/i.test(xmlish) || /<[\w:]*EntitiesDescriptor/i.test(xmlish)) {
      return { kind: 'samlmeta' };
    }
    if (/<[\w:]*LogoutRequest/i.test(xmlish) || /<[\w:]*LogoutResponse/i.test(xmlish)) {
      return { kind: 'samllogout' };
    }
    if (/<[\w:]*AuthnRequest/i.test(xmlish)) return { kind: 'samlreq' };
    if (/<[\w:]*Response/i.test(xmlish)) return { kind: 'samlresp' };
    if (/<[\w:]*Assertion/i.test(xmlish)) return { kind: 'samlresp' };
    // Parses as XML but the root is not one of the SAML elements. Running the
    // SAML checks over it would produce a page of findings about a document
    // that was never SAML, so hand it to diagnose instead.
    return { kind: null, reason: 'XML, but not a document authlint knows' };
  }

  // Long base64 that decodes to bytes rather than text: the redirect
  // binding's raw-DEFLATE payload. Only the binary case routes here; base64
  // of readable text falls through to diagnose, which explains it better.
  const blob = text.replace(/\s+/g, '');
  if (/^[A-Za-z0-9+/=_%-]{40,}$/.test(blob)) {
    let peek = null;
    try {
      let c = blob;
      if (/%[0-9a-fA-F]{2}/.test(c)) { try { c = decodeURIComponent(c); } catch (e) {} }
      peek = b64urlToText(c.slice(0, Math.floor(Math.min(c.length, 400) / 4) * 4));
    } catch (e) { /* not base64 after all */ }
    if (peek && /[\x00-\x08\x0e-\x1f]/.test(peek)) {
      return { kind: 'samlresp', maybeDeflate: true };
    }
  }

  // A bare query string, which is what you get from copying out of a HAR file.
  if (/(^|[?&])(response_type|client_id|redirect_uri|code_challenge)=/.test(text)) {
    return { kind: 'authz', asQuery: true };
  }

  return { kind: null, reason: 'authlint cannot tell what this is' };
}

function peekBase64Xml(text) {
  const candidate = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/=_-]{40,}$/.test(candidate)) return null;
  try {
    // Slice on a 4-character boundary so the peek does not fail on padding.
    const head = candidate.slice(0, Math.floor(Math.min(candidate.length, 400) / 4) * 4);
    const decoded = b64urlToText(head);
    return /^\s*</.test(decoded) ? decoded : null;
  } catch (e) { return null; }
}
