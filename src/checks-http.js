/* ============================== HTTP-SIDE ARTIFACTS ==============================
   The two most-pasted artifacts in any OAuth debugging session are the token
   endpoint's JSON response and a Set-Cookie header, and both used to be turned
   away at the door. The cookie's value is usually opaque; its ATTRIBUTES are
   not, and misconfigured cookie attributes are the most common web-auth defect
   there is. */

function checkTokenResponse(j, now) {
  const f = [];

  /* RFC 7662 introspection response: it has "active", a token response does not. */
  if (typeof j.active === 'boolean') {
    f.push(F('ok', 'Introspection response, active: ' + j.active, '', '', 'RFC 7662 §2.2'));
    if (j.active === false) {
      const extras = Object.keys(j).filter(k => k !== 'active');
      if (extras.length) {
        f.push(F('warn', 'Inactive, and the response still carries: ' + extras.join(', '),
          'An introspection response for an inactive token is supposed to say nothing else, ' +
          'because every extra member leaks what the token used to be to whoever is probing.',
          'Return {"active": false} and nothing more.', 'RFC 7662 §2.2'));
      }
    } else {
      const exp = typeof j.exp === 'number' ? j.exp : null;
      if (exp == null) {
        f.push(F('note', 'active:true with no exp',
          'The caller cannot cache this answer safely, so it will either hammer the introspection ' +
          'endpoint or cache blind.', '', 'RFC 7662 §2.2'));
      } else if (exp < now) {
        f.push(F('warn', 'active:true but exp is ' + secondsToHuman(now - exp) + ' in the past',
          'The two members contradict each other, and callers believe active.',
          'Fix the introspection endpoint.', 'RFC 7662 §2.2'));
      }
      if (!j.scope) {
        f.push(F('note', 'No scope in the introspection response',
          'The resource server knows the token is alive and not what it is allowed to do.', '',
          'RFC 7662 §2.2'));
      }
    }
    return sortFindings(f);
  }

  if (j.error) {
    f.push(F('note', 'Token endpoint error: ' + j.error +
      (j.error_description ? ' — ' + j.error_description : ''),
      'The description is the provider\'s, not authlint\'s.', '', 'RFC 6749 §5.2'));
    return sortFindings(f);
  }

  if (!j.access_token) {
    f.push(F('warn', 'No access_token',
      'This is shaped like a token response and the one required member is missing.', '',
      'RFC 6749 §5.1'));
  }
  if (!j.token_type) {
    f.push(F('warn', 'No token_type',
      'Required, and clients that assume Bearer on its absence will be wrong the day this ' +
      'deployment turns on DPoP.', 'Return token_type.', 'RFC 6749 §5.1'));
  } else if (/^bearer$/i.test(String(j.token_type)) && j.token_type !== 'Bearer') {
    f.push(F('note', 'token_type is "' + j.token_type + '"',
      'The value is case-insensitive in the spec and a surprising number of clients string-match ' +
      '"Bearer" exactly. This casing will break some of them.', '', 'RFC 6749 §5.1'));
  } else if (/^dpop$/i.test(String(j.token_type))) {
    f.push(F('ok', 'token_type is DPoP: the access token is sender-constrained', '', '', 'RFC 9449 §5'));
  }

  const ein = typeof j.expires_in === 'number' ? j.expires_in
            : (typeof j.expires_in === 'string' && /^\d+$/.test(j.expires_in) ? Number(j.expires_in) : null);
  if (j.expires_in == null) {
    f.push(F('warn', 'No expires_in',
      'Clients that are not told guess, and they guess long. The token\'s own exp only helps if ' +
      'it is a JWT and the client decodes it, which clients are told not to do.',
      'Return expires_in.', 'RFC 6749 §5.1'));
  } else if (ein != null && ein > 86400) {
    f.push(F('warn', 'expires_in is ' + secondsToHuman(ein),
      'A bearer access token living longer than a day is a long time for something with no ' +
      'revocation.', 'Minutes to an hour, with a refresh token for continuity.'));
  } else if (typeof j.expires_in === 'string') {
    f.push(F('note', 'expires_in is a string, not a number',
      'The spec value is numeric. Clients doing arithmetic on this get NaN and treat the token ' +
      'as expired, or worse, as never expiring.', 'Emit a number.', 'RFC 6749 §5.1'));
  }

  if (j.refresh_token) {
    f.push(F('note', 'A refresh token was issued',
      'Long-lived by design, so it is the artifact worth protecting most. For public clients the ' +
      'requirement is one of two things: sender-constrain it, or rotate it on every use with ' +
      'reuse detection revoking the family.',
      'Confirm rotation or sender-constraining is on.', 'RFC 9700 §4.14.2'));
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(String(j.refresh_token))) {
      f.push(F('note', 'The refresh token is a JWT',
        'Decodable by anyone who holds it, so whatever claims are inside are readable in every ' +
        'log it lands in. Paste it alone to check the contents.', ''));
    }
  }

  if (j.scope == null) {
    f.push(F('note', 'No scope in the response',
      'Granted scope is only required in the response when it differs from what was requested, ' +
      'so absence means "exactly what you asked for". A client that assumes more finds out at ' +
      'the resource server.', '', 'RFC 6749 §5.1'));
  } else {
    const scopes = String(j.scope).split(/\s+/).filter(Boolean);
    if (scopes.some(s => /^(.*\.)?(\*|all|full_access|admin)$/i.test(s))) {
      f.push(F('warn', 'Broad scope granted: ' + j.scope,
        'The token is as powerful as this list says, everywhere it lands.',
        'Grant the narrowest scope the client needs.'));
    }
  }

  if (j.access_token && !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(String(j.access_token))) {
    f.push(F('note', 'The access token is opaque',
      'Nothing to decode, which is a legitimate design: the resource server asks the issuer via ' +
      'introspection instead of reading claims. The findings that matter for it are on the ' +
      'introspection side.', '', 'RFC 7662'));
  }
  if (j.access_token || j.id_token) {
    f.push(F('note', 'Any JWT in this response is checked separately below',
      'The access_token and id_token values get their own findings sections when they decode.', ''));
  }

  return sortFindings(f);
}

/* ------------------------------ cookies ------------------------------ */

function parseSetCookieLine(line) {
  const body = line.replace(/^set-cookie:\s*/i, '');
  const parts = body.split(';');
  const eq = parts[0].indexOf('=');
  if (eq < 0) return null;
  const out = { name: parts[0].slice(0, eq).trim(), value: parts[0].slice(eq + 1).trim(),
                attrs: {}, raw: body };
  for (const p of parts.slice(1)) {
    const t = p.trim();
    if (!t) continue;
    const i = t.indexOf('=');
    if (i < 0) out.attrs[t.toLowerCase()] = true;
    else out.attrs[t.slice(0, i).trim().toLowerCase()] = t.slice(i + 1).trim();
  }
  return out;
}

function checkCookie(text, now) {
  const f = [];
  const lines = String(text).split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  if (/^cookie:/i.test(lines[0])) {
    f.push(F('note', 'This is the request-side Cookie header',
      'The attributes that decide a cookie\'s security (Secure, HttpOnly, SameSite, Domain) are ' +
      'set by the response and are not visible here.',
      'Paste the Set-Cookie response header to check them.', 'RFC 6265 §4.2'));
    const body = lines.join(' ').replace(/^cookie:\s*/i, '');
    if (body.length > 4096) {
      f.push(F('warn', 'Cookie header is ' + body.length.toLocaleString() + ' bytes',
        'Past the size where servers start rejecting requests outright, and the user who hits it ' +
        'cannot fix it themselves.', 'Slim the cookies.'));
    }
    const jwt = body.match(/[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/);
    if (jwt) {
      f.push(F('note', 'One of these values is a JWT',
        'Paste it alone and the token checks run on it.', ''));
    }
    return sortFindings(f);
  }

  for (const line of lines) {
    if (!/^set-cookie:/i.test(line) && lines.length > 1) continue;
    const c = parseSetCookieLine(/^set-cookie:/i.test(line) ? line : 'Set-Cookie: ' + line);
    if (!c) continue;
    const a = c.attrs;
    const who = '"' + c.name + '"';
    const sameSite = String(a.samesite || '').toLowerCase();

    if (/^__Host-/.test(c.name)) {
      const bad = [];
      if (!a.secure) bad.push('Secure is missing');
      if (a.domain) bad.push('Domain is set');
      if (String(a.path) !== '/') bad.push('Path is not /');
      if (bad.length) {
        f.push(F('critical', who + ' breaks its own __Host- prefix: ' + bad.join(', '),
          'The prefix is a contract the browser enforces: Secure, no Domain, Path=/. Broken, the ' +
          'browser rejects the whole cookie, silently, and login works in testing and fails in the field.',
          'Meet the prefix contract or drop the prefix.', 'RFC 6265bis (cookie prefixes)'));
      } else {
        f.push(F('ok', who + ' honours the __Host- prefix', ''));
      }
    } else if (/^__Secure-/.test(c.name) && !a.secure) {
      f.push(F('critical', who + ' has the __Secure- prefix without the Secure attribute',
        'The browser rejects it outright.', 'Add Secure.', 'RFC 6265bis (cookie prefixes)'));
    }

    if (sameSite === 'none' && !a.secure) {
      f.push(F('critical', who + ' is SameSite=None without Secure',
        'Browsers reject this combination, so the cookie is never stored, and the symptom is a ' +
        'login loop nobody can reproduce locally over https.',
        'SameSite=None requires Secure.', 'RFC 6265bis'));
    } else if (!a.secure) {
      f.push(F('critical', who + ' has no Secure attribute',
        'The browser will attach it to plaintext http requests to the same host, where anyone on ' +
        'the path can read it. For a session cookie that is session theft.',
        'Add Secure.', 'RFC 6265 §4.1.2.5'));
    }

    const csrfish = /csrf|xsrf/i.test(c.name);
    if (!a.httponly && !csrfish) {
      f.push(F('warn', who + ' is readable by script (no HttpOnly)',
        'Every script on the page, including every injected one, can read it. XSS anywhere on ' +
        'the origin becomes session theft.',
        'Add HttpOnly unless JavaScript genuinely has to read this cookie.', 'RFC 6265 §4.1.2.6'));
    }
    if (!sameSite) {
      f.push(F('note', who + ' has no SameSite attribute',
        'Behaviour then differs by browser: some default to Lax, some to None. Whatever you ' +
        'meant, say it, because the default you tested is not the default everywhere.',
        'State SameSite explicitly.', 'RFC 6265bis'));
    } else if (sameSite === 'none' && a.secure) {
      f.push(F('note', who + ' is SameSite=None',
        'Sent on every cross-site request, which is what enables both third-party use and CSRF. ' +
        'Deliberate for embedded flows; a plain session cookie wants Lax or Strict.', '', 'RFC 6265bis'));
    }
    if (a.domain) {
      f.push(F('note', who + ' is scoped to Domain=' + a.domain,
        'It is sent to every subdomain of ' + a.domain + ', so one XSS-able or takeover-able ' +
        'subdomain can read or overwrite it. Host-only (no Domain attribute) is tighter.',
        '', 'RFC 6265 §4.1.2.3'));
    }

    const maxAge = a['max-age'] != null && /^\d+$/.test(String(a['max-age'])) ? Number(a['max-age']) : null;
    if (maxAge != null && maxAge > 2592000 && !csrfish) {
      f.push(F('note', who + ' lives for ' + secondsToHuman(maxAge),
        'A month-plus cookie outlives most password changes and every "log out everywhere" ' +
        'button that only clears server sessions it knows about.',
        'Pair long cookies with server-side revocation.', ''));
    }

    if (/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/.test(c.value)) {
      f.push(F('note', who + ' carries a JWT (' + c.value.length + ' characters)',
        'Paste the value alone and the token checks run on it. JWTs in cookies also eat the 4KB ' +
        'per-cookie budget fast, and the browser drops an oversized cookie without a word.',
        '', ''));
    }
    if ((c.name + '=' + c.value).length > 4096) {
      f.push(F('warn', who + ' is over 4KB',
        'Browsers drop oversized cookies silently: no error, no console line, just a login that ' +
        'never sticks.', 'Slim it, or move the payload server-side.', 'RFC 6265 §6.1'));
    }
  }

  if (!f.length) {
    f.push(F('note', 'No Set-Cookie lines found',
      'Paste the header as it appears in the response, one Set-Cookie per line.', ''));
  }
  return sortFindings(f);
}
