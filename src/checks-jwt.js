/* ============================== JWT CHECKS ==============================
   Ordered roughly by how much trouble each one causes. The header checks come
   first because every one of them is a way to make a verifier trust a token it
   should have rejected, and those are the bugs that end up in advisories.

   Not every three-segment token is the same artifact. An ID token, an access
   token, a DPoP proof and a logout token carry different required claims, and
   grading one against another's rules produces confident nonsense: a DPoP
   proof has no exp BY DESIGN, and telling its author "this token is valid
   forever" is worse than saying nothing. So the first thing that happens here
   is working out which kind of token this is. */

function jwtProfile(t) {
  const h = t.header || {};
  const p = t.payload || {};
  const typ = String(h.typ || '').toLowerCase();
  if (t.kind === 'jwe') return 'jwe';
  if (typ === 'dpop+jwt') return 'dpop';
  if (typ === 'logout+jwt') return 'logout';
  if (p.events && typeof p.events === 'object' &&
      Object.keys(p.events).some(k => /backchannel-logout/i.test(k))) return 'logout';
  if (p.htm && p.htu) return 'dpop';   // the shape of a proof, even without the typ
  if (typ === 'at+jwt' || typ === 'application/at+jwt') return 'at';
  if (p.nonce !== undefined || p.at_hash !== undefined || p.auth_time !== undefined) return 'id';
  if (p.scope || p.scp || p.client_id) return 'at';
  return 'jwt';
}

/* A claim that should be a NumericDate but arrived as a string. Several stacks
   emit "1756000000" and several validators then fail OPEN: the typeof check
   misses, no branch runs, and the token never expires as far as that code is
   concerned. Returns the numeric value so the time checks still happen. */
function numericDate(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return null;
}

function checkJwt(t, now) {
  const prof = jwtProfile(t);
  if (prof === 'jwe') return checkJwe(t, now);
  if (prof === 'dpop') return checkDpopProof(t, now);

  const f = [];
  const h = t.header || {};
  const p = t.payload || {};
  const alg = String(h.alg || '');

  /* ---------------- header: the ways a verifier gets fooled ---------------- */

  if (!h.alg) {
    f.push(F('critical', 'No alg in the header',
      'A verifier that reads the algorithm from the token has nothing to read, and one that ' +
      'defaults on a missing value will pick something.',
      'Pin the expected algorithm in the verifier and reject anything else.', 'RFC 7515 §4.1.1'));
  } else if (/^none$/i.test(alg)) {
    f.push(F('critical', 'alg is "none", so this token is unsigned',
      'Anyone can change the payload and the token still parses. If any verifier in the chain ' +
      'honours the header algorithm, this is a straight authentication bypass.',
      'Reject alg=none unconditionally. Pin the algorithm you expect rather than reading it from the token.',
      'CVE-2015-9235, RFC 8725 §3.1'));
  } else if (/^HS/i.test(alg)) {
    f.push(F('warn', 'Symmetric signature (' + alg + ')',
      'Everyone who can verify this token can also mint one, because the verification key is the ' +
      'signing key. If a provider that normally signs with RS256 issued this, the classic algorithm ' +
      'confusion attack looks exactly like it: the attacker re-signs with the public key as an HMAC secret.',
      'Prefer RS256 or ES256 for anything crossing a trust boundary, and pin the algorithm on verification.',
      'RFC 8725 §2.1'));
  }

  if (h.jku) {
    f.push(F('critical', 'Header carries jku, a URL the verifier is asked to fetch keys from',
      'If the verifier follows that URL and trusts what comes back, whoever controls the token ' +
      'controls the signing key. That is forgery with extra steps, and following it blindly is ' +
      'also a server-side request forgery.',
      'Ignore jku, or resolve it only against a fixed allow-list of hosts you own.', 'RFC 8725 §3.10'));
  }
  if (h.x5u) {
    f.push(F('critical', 'Header carries x5u, a URL pointing at the signing certificate',
      'Same failure as jku. An attacker who can set this field can nominate the key that validates ' +
      'their own token.',
      'Ignore x5u, or allow-list the host.', 'RFC 8725 §3.10'));
  }
  if (h.jwk) {
    f.push(F('critical', 'Header embeds its own public key (jwk)',
      'The token is telling the verifier which key to trust. Any verifier that believes it will ' +
      'accept a token signed by anyone. (The one artifact where an embedded jwk is required is a ' +
      'DPoP proof, and this token does not look like one.)',
      'Never take the key from the token. Resolve kid against a JWKS you fetched yourself.', 'RFC 8725 §3.10'));
  }
  if (!h.kid && /^(RS|ES|PS)/i.test(alg)) {
    f.push(F('note', 'No kid',
      'The verifier has to try every key in the set, and rotating a key becomes a flag day rather ' +
      'than a rollout.',
      'Have the issuer stamp kid and publish matching kids in the JWKS.', 'RFC 7515 §4.1.4'));
  }
  if (prof === 'at' && String(h.typ || '').toLowerCase() === 'jwt') {
    f.push(F('note', 'Access token typed as "JWT" rather than "at+jwt"',
      'Explicit typing is what stops a resource server accepting an ID token where it expected an ' +
      'access token. The two are both JWTs and both signed by the same issuer.',
      'Issue access tokens with typ=at+jwt and check it.', 'RFC 9068 §2.1, RFC 8725 §3.11'));
  }
  if (h.crit) {
    f.push(F('note', 'crit header present: ' + JSON.stringify(h.crit),
      'A verifier that does not understand every extension listed here is required to reject the ' +
      'token. Many libraries quietly do not.', '', 'RFC 7515 §4.1.11'));
  }

  if (t.kind === 'jws' && !t.signature) {
    f.push(F('critical', 'Empty signature segment',
      'The token claims an algorithm and carries nothing to verify. Some libraries have historically ' +
      'treated this as valid.',
      'Reject tokens with an empty signature.', 'RFC 8725 §3.1'));
  }

  /* ---------------- time ---------------- */

  for (const k of ['exp', 'iat', 'nbf']) {
    if (typeof p[k] === 'string') {
      f.push(F('critical', k + ' is a string, not a number: "' + String(p[k]).slice(0, 24) + '"',
        'NumericDate is a JSON number. Validators that check typeof before comparing fail OPEN on ' +
        'a string: no branch runs, no error is raised, and the token never expires as far as that ' +
        'code is concerned.',
        'Emit ' + k + ' as a number at the issuer.', 'RFC 7519 §2'));
    }
  }
  const exp = numericDate(p.exp), iat = numericDate(p.iat), nbf = numericDate(p.nbf);

  if (looksLikeMillis(exp) || looksLikeMillis(iat) || looksLikeMillis(nbf)) {
    f.push(F('critical', 'Timestamps look like milliseconds, not seconds',
      'JWT time claims are seconds since the epoch. A millisecond value puts the expiry thousands ' +
      'of years out, so the token never expires and nobody notices until it is abused.',
      'Divide by 1000 at the issuer.', 'RFC 7519 §2 (NumericDate)'));
  }

  if (p.exp == null) {
    f.push(F('critical', 'No exp claim',
      'The token is valid forever. Whatever leaks it, leaks it permanently: a log line, a browser ' +
      'history entry, a support ticket screenshot.',
      'Always set exp. Minutes for access tokens, not hours.', 'RFC 7519 §4.1.4'));
  } else if (exp != null && !looksLikeMillis(exp)) {
    const remaining = exp - now;
    if (remaining < 0) {
      f.push(F('note', 'Expired ' + secondsToHuman(-remaining) + ' ago',
        'Stated so you know the token you are looking at is not the one currently failing, if it is failing now.'));
    } else {
      f.push(F('ok', 'Valid for another ' + secondsToHuman(remaining), ''));
    }
    if (iat != null) {
      const life = exp - iat;
      if (life < 0) {
        f.push(F('critical', 'exp is before iat',
          'The token expired before it was issued. Something is assembling these claims by hand, ' +
          'and time-of-check bugs travel in groups.',
          'Fix the issuer.', 'RFC 7519 §4.1.4'));
      } else if (life > 31536000) {
        f.push(F('critical', 'Lifetime is ' + secondsToHuman(life),
          'A bearer token this long-lived is a password that nobody can rotate and everybody logs.',
          'Shorten it and refresh instead.'));
      } else if (life > 86400) {
        f.push(F('warn', 'Lifetime is ' + secondsToHuman(life),
          'Long enough that revocation matters, and bearer tokens have no revocation.',
          'Minutes for access tokens. If you need longer sessions, use a refresh token you can revoke.'));
      } else {
        f.push(F('ok', 'Lifetime is ' + secondsToHuman(life), ''));
      }
    }
  }

  if (iat != null && iat - now > 300) {
    f.push(F('warn', 'Issued ' + secondsToHuman(iat - now) + ' in the future',
      'Either a clock is wrong or the token was minted somewhere you did not expect. Verifiers with ' +
      'tight skew tolerance will reject it intermittently, which is the worst kind of bug to chase.',
      'Fix time sync at the issuer before you widen the skew allowance.'));
  }
  if (nbf != null && nbf - now > 60) {
    f.push(F('note', 'Not valid for another ' + secondsToHuman(nbf - now), ''));
  }

  /* ---------------- identity of the parties ---------------- */

  if (!p.iss) {
    f.push(F('critical', 'No iss claim',
      'Nothing says who minted this. A verifier that does not check the issuer will accept a ' +
      'correctly signed token from a completely different tenant.',
      'Set iss, and compare it exactly against the expected issuer.', 'OIDC Core §2'));
  } else if (typeof p.iss === 'string' && /^http:\/\//i.test(p.iss)) {
    // Caught separately from the general case below: the earlier version of
    // this check allowed anything with a scheme through, which meant a
    // plaintext http issuer was never reported at all.
    f.push(F('warn', 'iss is a plaintext http URL: ' + p.iss,
      'Discovery against a plaintext issuer can be rewritten in transit, and the keys a client ' +
      'ends up trusting come from whatever answered.',
      'Serve the issuer over https.', 'OIDC Discovery §4.3'));
  } else if (typeof p.iss === 'string' && !/^https:\/\//.test(p.iss) && !/^[a-z][a-z0-9+.-]*:/i.test(p.iss)) {
    f.push(F('note', 'iss is not a URL: ' + p.iss,
      'Legal for a plain JWT, and OpenID Connect requires an https URL because discovery depends ' +
      'on the value matching the issuer exactly, trailing slash and all.', '', 'OIDC Discovery §4.3'));
  } else if (typeof p.iss === 'string' && /^https:\/\/.+\/$/.test(p.iss)) {
    f.push(F('note', 'iss ends with a trailing slash: ' + p.iss,
      'Issuer comparison is exact string equality. If the discovery document, the token and the ' +
      'client configuration do not agree byte for byte, trailing slash included, validation fails ' +
      'with an error that never mentions the slash.',
      'Make iss match the advertised issuer exactly, and check where the slash lives.', 'OIDC Discovery §4.3'));
  }

  if (p.aud == null) {
    f.push(F('warn', 'No aud claim',
      'Nothing scopes this token to a recipient, so any service holding it can present it to any ' +
      'other service that trusts the same issuer.',
      'Set aud to the intended recipient and verify it there.', 'RFC 7519 §4.1.3'));
  } else if (prof === 'id' && Array.isArray(p.aud) && p.aud.length > 1 && !p.azp) {
    f.push(F('note', 'ID token with multiple audiences and no azp',
      'A client validating this token is advised to check that azp is present when aud is ' +
      'multi-valued, so it can confirm it is the party the token was issued to. Without azp that ' +
      'check cannot happen. (On an access token a multi-valued aud is normal and azp is not expected.)',
      'Add azp naming the client this token was issued to, or issue one token per audience.',
      'OIDC Core §2, §3.1.3.7'));
  }

  if (prof === 'logout' && p.nonce !== undefined) {
    f.push(F('critical', 'Logout token carries a nonce',
      'A logout token is prohibited from carrying a nonce, precisely so it can never be replayed ' +
      'into an ID token slot. One that carries it anyway defeats that separation.',
      'Remove nonce at the issuer.', 'OIDC Back-Channel Logout §2.4'));
  }

  if (!p.sub && (p.iss || p.aud) && prof !== 'logout') {
    f.push(F('warn', 'No sub claim',
      'There is no stable identifier for the principal, so the relying party has to fall back on ' +
      'something mutable to key its own records.',
      'Set sub to an identifier that never changes and is never reused.', 'RFC 7519 §4.1.2'));
  } else if (looksLikeEmail(p.sub)) {
    f.push(F('warn', 'sub is an email address',
      'People change their surname and companies recycle addresses. When that happens, either an ' +
      'account is orphaned or someone inherits the previous holder\'s access.',
      'Use an opaque immutable identifier for sub and carry the email as a separate claim.',
      'OIDC Core §5.7'));
  }

  if (!p.jti && exp != null && (exp - now) > 900) {
    f.push(F('note', 'No jti',
      'Nothing to record if you ever need to deny a specific token before it expires.',
      'Add jti if you plan to support revocation.', 'RFC 7519 §4.1.7'));
  }

  if (p.cnf && (p.cnf.jkt || p.cnf['x5t#S256'])) {
    f.push(F('ok', 'Sender-constrained token (cnf.' + (p.cnf.jkt ? 'jkt' : 'x5t#S256') + ')',
      'This token is bound to a key. A thief without that key cannot use it, which is the single ' +
      'biggest upgrade over a bearer token.', '', p.cnf.jkt ? 'RFC 9449 §6.1' : 'RFC 8705 §3'));
  } else if (prof === 'at') {
    f.push(F('note', 'Bearer token: no cnf binding',
      'Anyone who holds this token can use it. DPoP or mutual-TLS binding (a cnf claim) makes a ' +
      'stolen token useless without the key it was bound to.',
      'Consider sender-constraining tokens for anything sensitive.', 'RFC 9449, RFC 8705'));
  }

  /* ---------------- what is being carried ---------------- */

  const pii = PII_CLAIMS.filter(c => p[c] !== undefined);
  if (pii.length) {
    f.push(F(pii.length > 3 ? 'warn' : 'note', 'Personal data in the token: ' + pii.join(', '),
      'A JWT is base64, not encryption. Everything here is readable in any log aggregator, proxy ' +
      'access log, browser history entry and error report the token passes through.',
      'Carry an identifier and let the relying party fetch what it needs from userinfo.',
      'RFC 7519 §12'));
  }
  for (const k of Object.keys(p)) {
    const v = p[k];
    if (typeof v === 'string' && /^-{2,5}BEGIN|^[A-Za-z0-9+/]{200,}={0,2}$/.test(v)) {
      f.push(F('warn', 'Claim "' + k + '" looks like embedded key material or a nested credential',
        'Anything readable in the token is readable by everything the token touches.', ''));
      break;
    }
  }

  const size = (t.raw || '').length;
  if (size > 8192) {
    f.push(F('critical', 'Token is ' + size.toLocaleString() + ' bytes',
      'Past the default header limit on most servers and proxies. This fails as a 431 or a silently ' +
      'truncated header, usually only for the users with the most group memberships.',
      'Move the large claims out. Group lists are the usual culprit.'));
  } else if (size > 4096) {
    f.push(F('warn', 'Token is ' + size.toLocaleString() + ' bytes',
      'Too big for a single cookie, and close enough to common header limits that a user with a few ' +
      'more roles than average will break.',
      'Move group and permission lists out of the token.'));
  }

  for (const k of ['roles', 'groups', 'permissions', 'scp', 'entitlements']) {
    if (Array.isArray(p[k]) && p[k].length > 40) {
      f.push(F('warn', k + ' has ' + p[k].length + ' entries',
        'This is the claim that grows until the token stops fitting in a header, and it grows for ' +
        'your longest-serving employees first.',
        'Look these up at the resource server instead of carrying them.'));
    }
  }

  /* ---------------- the reminder that matters most ---------------- */
  f.push(F('note', 'authlint did not verify the signature',
    'Nothing here proves this token is genuine. A decoded token tells you what it claims, not ' +
    'whether the claim is true, and every finding above is about content rather than authenticity.',
    'Verify against the issuer\'s JWKS in your own code, with the algorithm pinned.'));

  return sortFindings(f);
}

/* ============================== DPoP PROOF ==============================
   A DPoP proof is not an access token, and grading it as one produces exactly
   backwards advice: the embedded jwk is REQUIRED, and exp, iss and aud are not
   defined for it at all. */
function checkDpopProof(t, now) {
  const f = [];
  const h = t.header || {};
  const p = t.payload || {};
  const alg = String(h.alg || '');
  const typ = String(h.typ || '').toLowerCase();

  if (typ === 'dpop+jwt') {
    f.push(F('ok', 'DPoP proof (typ dpop+jwt)', ''));
  } else {
    f.push(F('warn', 'Shaped like a DPoP proof but typ is "' + (h.typ || 'absent') + '"',
      'The htm/htu claims say proof, the type header does not. Servers are required to reject a ' +
      'proof whose typ is not dpop+jwt, and explicit typing is what keeps a proof from being ' +
      'replayed as some other kind of token.',
      'Set typ to dpop+jwt at the client.', 'RFC 9449 §4.2, RFC 8725 §3.11'));
  }

  if (!h.alg || /^none$/i.test(alg)) {
    f.push(F('critical', 'Proof algorithm is ' + (h.alg ? '"none"' : 'missing'),
      'An unsigned proof proves nothing.', 'Sign with an asymmetric algorithm.', 'RFC 9449 §4.2'));
  } else if (/^HS/i.test(alg)) {
    f.push(F('critical', 'DPoP proof signed with a symmetric algorithm (' + alg + ')',
      'The whole point of the proof is possession of a private key the server does not hold. With ' +
      'HMAC the verifier holds the same key, so possession proves nothing.',
      'Use an asymmetric algorithm such as ES256.', 'RFC 9449 §4.2'));
  }

  if (!h.jwk) {
    f.push(F('critical', 'No jwk in the header',
      'A DPoP proof carries its public key in the header by definition; that is the key the server ' +
      'checks the signature with and hashes into the token binding.',
      'Include the public key as jwk.', 'RFC 9449 §4.2'));
  } else if (h.jwk.d || h.jwk.p || h.jwk.q) {
    f.push(F('critical', 'The jwk in this proof includes PRIVATE key parameters',
      'd, p and q are the private half. Every server this proof is sent to now holds the key that ' +
      'was supposed to prove possession.',
      'Send only the public parameters, and rotate this key now.', 'RFC 9449 §4.2'));
  } else {
    f.push(F('ok', 'Header embeds the proof public key (jwk), as a DPoP proof must', '',
      '', 'RFC 9449 §4.2'));
  }

  for (const [k, why] of [
    ['jti', 'nothing identifies this proof for replay tracking'],
    ['htm', 'nothing binds the proof to an HTTP method'],
    ['htu', 'nothing binds the proof to a target URI'],
    ['iat', 'nothing bounds how old a replayed proof can be']]) {
    if (p[k] === undefined) {
      f.push(F('critical', 'No ' + k + ' claim', 'Required in every DPoP proof: ' + why + '.',
        'Add ' + k + ' at the client.', 'RFC 9449 §4.2'));
    }
  }

  if (typeof p.htu === 'string' && /[?#]/.test(p.htu)) {
    f.push(F('warn', 'htu carries a query or fragment: ' + p.htu,
      'htu is the target URI without query and fragment. Servers compare it after stripping ' +
      'both, and a client that includes them fails against strict implementations.',
      'Send scheme, host and path only.', 'RFC 9449 §4.2'));
  }

  const iat = numericDate(p.iat);
  if (iat != null) {
    const age = now - iat;
    if (age > 300) {
      f.push(F('note', 'Proof is ' + secondsToHuman(age) + ' old',
        'Servers accept proofs only within a narrow window, typically seconds to a few minutes. ' +
        'This one would be rejected as stale by most.', '', 'RFC 9449 §11.1'));
    } else if (age < -300) {
      f.push(F('warn', 'Proof is issued ' + secondsToHuman(-age) + ' in the future',
        'A clock is wrong on one side, and proof acceptance windows are tight.', 'Fix time sync.'));
    }
  }

  if (p.ath) {
    f.push(F('note', 'Bound to an access token (ath present)',
      'This proof accompanies a specific access token: ath is the hash of it. The server must ' +
      'compare that hash against the token actually presented.', '', 'RFC 9449 §4.3'));
  }
  if (p.nonce) {
    f.push(F('note', 'Carries a server-issued nonce',
      'The server demanded fresh proofs via DPoP-Nonce, and this proof echoes it.', '', 'RFC 9449 §8'));
  }

  for (const k of ['exp', 'iss', 'aud', 'sub']) {
    if (p[k] !== undefined) {
      f.push(F('note', k + ' is present, but not defined for a DPoP proof',
        'Freshness comes from iat and the server\'s window, identity from the key, audience from ' +
        'htu. Verifiers ignore this claim, so nothing enforces whatever it promises.', '', 'RFC 9449 §4.2'));
    }
  }

  f.push(F('note', 'authlint did not verify the proof signature',
    'Whether the signature validates against the embedded key, and whether that key matches the ' +
    'cnf.jkt in the access token it accompanies, are the checks that make DPoP real. Both need ' +
    'your code.', 'Verify the proof with the embedded jwk, then compare its thumbprint to cnf.jkt.',
    'RFC 9449 §4.3, §6.1'));

  return sortFindings(f);
}

/* ============================== JWE ==============================
   Five segments, an encrypted payload, and a different set of questions. The
   header alg here is KEY MANAGEMENT, not a signature: flagging RSA-OAEP as "no
   kid on an asymmetric signature" or demanding exp from a payload nobody can
   read are the mistakes this function exists to not make. */
function checkJwe(t, now) {
  const f = [];
  const h = t.header || {};
  const alg = String(h.alg || '');
  const enc = String(h.enc || '');

  f.push(F('note', 'This is a JWE, so the payload is encrypted',
    'authlint can read the header but not the content, which is the point of a JWE. Everything ' +
    'below is about the header; the claims inside cannot be checked without the key.', '', 'RFC 7516'));

  if (!alg) {
    f.push(F('critical', 'No alg (key management algorithm) in the header',
      'Nothing says how the content key was protected.', '', 'RFC 7516 §4.1.1'));
  } else if (/^RSA1_5$/i.test(alg)) {
    f.push(F('warn', 'Key management is RSA1_5 (PKCS#1 v1.5)',
      'RSA1_5 decryption can be turned into a padding oracle wherever error behaviour differs ' +
      'between bad padding and bad plaintext, and that class of attack has been rediscovered ' +
      'against JOSE stacks repeatedly.',
      'Use RSA-OAEP or an ECDH-ES variant.', 'RFC 8017 §7.2, RFC 7518 §4.2'));
  } else if (/^dir$/i.test(alg)) {
    f.push(F('note', 'Direct symmetric encryption (alg dir)',
      'Producer and consumer share the content key outright. Fine inside one service; between ' +
      'parties it has the same everyone-can-mint property as HMAC signing.', '', 'RFC 7518 §4.5'));
  }
  if (!enc) {
    f.push(F('critical', 'No enc in the header',
      'A JWE without a content encryption algorithm is malformed.', '', 'RFC 7516 §4.1.2'));
  }
  if (h.zip) {
    f.push(F('warn', 'Compressed plaintext (zip: ' + h.zip + ')',
      'Compression before encryption invites decompression bombs on the consumer and can leak ' +
      'plaintext facts through ciphertext length.',
      'Avoid zip unless you control both ends and cap the inflated size.', 'RFC 8725 §3.6'));
  }
  if (h.jku || h.x5u) {
    f.push(F('warn', 'Header carries ' + (h.jku ? 'jku' : 'x5u') + ', a URL to resolve keys from',
      'Following a URL the artifact chose is a request-forgery primitive even when the payload is ' +
      'encrypted.', 'Resolve keys from configuration, not from the token.', 'RFC 8725 §3.10'));
  }

  const size = (t.raw || '').length;
  if (size > 8192) {
    f.push(F('warn', 'Token is ' + size.toLocaleString() + ' bytes',
      'Past the default header limit on most servers and proxies if this travels as a header.',
      'Check where it travels.'));
  }

  f.push(F('note', 'There is no signature on a JWE for authlint to verify',
    'Integrity here comes from the AEAD tag under the encryption key. If a signed token is nested ' +
    'inside (cty "JWT"), verify that inner signature after decrypting, and decrypt with the ' +
    'algorithms pinned.', '', 'RFC 7519 §5.2'));

  return sortFindings(f);
}
