/* ============================== SAML CHECKS ==============================
   SAML is where the interesting failures live, because the security of the
   whole exchange rests on which element the signature covers, and that is
   invisible unless you go looking. Every check here is something you cannot
   see by reading a decoded assertion in a text editor. */

const WEAK_SIG = /sha1|md5|dsa-sha1/i;

const SAML_ASSERT_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const SAML11_ASSERT_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/* SAML time values MUST be UTC with a trailing Z (Core §1.3.3). A zoneless
   timestamp is parsed as LOCAL time by JavaScript and by several SAML stacks,
   which silently shifts every window by the reader's UTC offset. Parse it as
   the UTC the spec requires, and say so. */
function samlInstant(v, f, what) {
  if (!v) return NaN;
  let s = String(v).trim();
  if (!/([zZ]|[+-]\d{2}:?\d{2})$/.test(s)) {
    if (f) {
      f.push(F('warn', what + ' has no timezone designator: ' + s,
        'SAML time values are required to be UTC with a trailing Z. A zoneless timestamp is read ' +
        'as local time by most date parsers, so the validity window silently shifts by whatever ' +
        'offset the reading machine happens to be in.',
        'Emit UTC with the Z suffix at the identity provider.', 'SAML 2.0 Core §1.3.3'));
    }
    s += 'Z';
  }
  return Date.parse(s);
}

function checkSamlResponse(x, now) {
  const f = [];
  const doc = x.doc;
  const root = doc.documentElement;
  const isResponse = /Response$/i.test(root.localName);
  const plainAssertions = els(root, 'Assertion');
  const encAssertions = els(root, 'EncryptedAssertion');
  const assertions = plainAssertions.concat(encAssertions);

  /* ---------------- status ---------------- */
  const sc = el(root, 'StatusCode');
  if (sc) {
    const v = attr(sc, 'Value') || '';
    if (!/:Success$/i.test(v)) {
      const inner = els(root, 'StatusCode')[1];
      const msg = el(root, 'StatusMessage');
      f.push(F('note', 'Status is not Success: ' + v.split(':').pop() +
        (inner ? ' / ' + String(attr(inner, 'Value')).split(':').pop() : ''),
        (msg && msg.textContent ? 'Provider message: ' + msg.textContent.trim() :
         'The identity provider refused. The second-level code is usually the useful one.')));
    } else {
      f.push(F('ok', 'Status: Success', ''));
    }
  }

  /* ---------------- the signature question, which is the whole game ---------------- */
  const allSigs = els(root, 'Signature');
  const responseSigned = allSigs.some(s => s.parentNode === root);
  const signedAssertions = plainAssertions.filter(a =>
    els(a, 'Signature').some(s => s.parentNode === a));

  if (!allSigs.length) {
    if (encAssertions.length) {
      f.push(F('warn', 'Nothing visible is signed, and the assertion is encrypted',
        'No signature covers the response, and whether the encrypted assertion is signed inside ' +
        'cannot be seen from here. If the inner assertion is unsigned too, anyone who can reach ' +
        'the assertion consumer service can log in as anyone.',
        'Verify the inner signature after decryption, on the element you consume.',
        'SAML 2.0 Core §5'));
    } else {
      f.push(F('critical', 'Nothing is signed',
        'There is no signature anywhere in this document, so nothing establishes that the identity ' +
        'provider produced it. Anyone who can reach the assertion consumer service can log in as anyone.',
        'Require signed assertions at the service provider and reject unsigned responses.',
        'SAML 2.0 Core §5'));
    }
  } else if (plainAssertions.length && !signedAssertions.length && responseSigned) {
    f.push(F('critical', 'The response is signed but the assertion inside it is not',
      'This is the classic SAML break. A service provider that validates the response signature and ' +
      'then reads the assertion can be fed a second, unsigned assertion wrapped into the document. ' +
      'The signature still verifies, because it covers the element it always covered.',
      'Sign the assertion, and validate the signature on the element you actually consume.',
      'XML signature wrapping'));
  } else if (!plainAssertions.length && encAssertions.length) {
    f.push(F(responseSigned ? 'ok' : 'note',
      'Assertion is encrypted' + (responseSigned ? ', and the response is signed' : ''),
      'Whether the assertion inside the ciphertext is also signed cannot be determined without ' +
      'decrypting it. Decrypt first, then verify the inner signature on the element you consume; ' +
      'a signature check that runs before decryption is checking the wrong thing.',
      '', 'SAML 2.0 Core §2.3.4'));
  } else if (signedAssertions.length) {
    f.push(F('ok', 'Assertion is signed' + (responseSigned ? ' (and so is the response)' : ''), ''));
  }

  if (assertions.length > 1) {
    f.push(F('critical', 'Document contains ' + assertions.length + ' assertions',
      'A legitimate response carries one. More than one is the shape of a signature wrapping attack, ' +
      'where the signed original is kept to satisfy verification and an injected copy is what gets read.',
      'Reject any response with more than one assertion.', 'XML signature wrapping'));
  }

  /* Look-alike elements. Matching on local names is what lets providers use
     any prefix, and it is also what an attacker exploits with an element NAMED
     Assertion in a namespace of their own. Check the namespace explicitly. */
  for (const a of plainAssertions) {
    const ns = a.namespaceURI || '';
    if (ns && ns !== SAML_ASSERT_NS && ns !== SAML11_ASSERT_NS) {
      f.push(F('critical', 'An element named Assertion is in a foreign namespace: ' + ns,
        'It is dressed as a SAML assertion and is not one. A consumer that matches elements by ' +
        'local name will read it; a signature that covers the real assertion will still verify.',
        'Reject it, and match elements by namespace as well as name in your own code.',
        'XML signature wrapping'));
    }
  }
  for (const s of allSigs) {
    const ns = s.namespaceURI || '';
    if (ns && ns !== DSIG_NS) {
      f.push(F('critical', 'An element named Signature is outside the XML DSig namespace: ' + ns,
        'It looks like a signature and no verifier will treat it as one. Its presence makes the ' +
        'document appear signed to a human reading it.',
        'Reject the document.', 'XML signature wrapping'));
    }
  }

  /* Duplicate IDs are the mechanism wrapping attacks rely on, and the ID map
     is also what lets each signature's Reference be resolved below. */
  const ids = {};
  const withId = doc.getElementsByTagName('*');
  let dupReported = false;
  for (let i = 0; i < withId.length; i++) {
    const node = withId[i];
    const id = node.getAttribute && (node.getAttribute('ID') || node.getAttribute('Id'));
    if (!id) continue;
    if (ids[id]) {
      if (!dupReported) {
        f.push(F('critical', 'Duplicate ID attribute: ' + id,
          'Signature references resolve by ID. Two elements sharing one means the element that gets ' +
          'verified and the element that gets read can be different elements.',
          'Reject the document.', 'XML signature wrapping'));
        dupReported = true;
      }
    } else {
      ids[id] = node;
    }
  }

  /* ---------------- what each signature actually covers ----------------
     This is the mechanism of every wrapping attack, not its symptoms: does the
     signature's Reference resolve, and is the element it resolves to the same
     element the signature sits inside? Everything above (assertion counts,
     duplicate IDs) infers wrapping; this observes it. */
  for (const s of allSigs) {
    const refs = els(s, 'Reference');
    if (!refs.length) {
      f.push(F('warn', 'A Signature carries no Reference',
        'Nothing states which element it signs, so no verifier can connect it to the content.',
        '', 'XML DSig Core §4.4'));
      continue;
    }
    if (refs.length > 1) {
      f.push(F('note', 'One Signature covers ' + refs.length + ' References',
        'Legal, and unusual in SAML. Each reference is a separately-resolved target, and each is ' +
        'a separate place for the resolved element and the consumed element to disagree.', ''));
    }
    for (const r of refs) {
      const uri = attr(r, 'URI');
      if (uri == null || uri === '') {
        f.push(F('warn', 'Signature Reference URI is empty (whole-document reference)',
          'It signs the entire document rather than one identified element. Anything inserted ' +
          'anywhere invalidates it, which sounds strong, and it also means no element is ' +
          'specifically bound: SAML profiles expect the signature to reference the element it ' +
          'protects by ID.',
          'Reference the Response or Assertion by its ID.', 'SAML 2.0 Core §5.4.2'));
      } else if (uri[0] === '#') {
        const target = ids[uri.slice(1)];
        if (!target) {
          f.push(F('critical', 'Signature Reference points at ' + uri + ', which does not exist',
            'The signature names an element this document does not contain. Whatever this ' +
            'signature once covered, it is not covering anything here.',
            'Reject the document.', 'XML DSig Core §4.4.3'));
        } else if (s.parentNode && s.parentNode !== target) {
          f.push(F('critical', 'The signature does not cover its own parent',
            'It sits inside <' + s.parentNode.localName + '> but signs <' + target.localName +
            '> (' + uri + '). An enveloped SAML signature covers the element it lives in; when it ' +
            'points elsewhere, the element that verifies and the element that gets consumed are ' +
            'different elements, which is XML signature wrapping observed directly.',
            'Validate the signature over the element you consume, and reject mismatches.',
            'SAML 2.0 Core §5.4.1'));
        } else {
          f.push(F('ok', 'Signature Reference resolves to the element it sits in (<' +
            target.localName + '>)', ''));
        }
      } else {
        f.push(F('warn', 'Signature Reference is external: ' + String(uri).slice(0, 80),
          'It points outside this document. Nothing a service provider resolves from elsewhere ' +
          'should decide whether this document is trusted.',
          'Use same-document ID references only.', 'SAML 2.0 Core §5.4.2'));
      }
    }
    const transforms = els(s, 'Transform').map(t => String(attr(t, 'Algorithm') || ''));
    if (transforms.some(a => /xpath/i.test(a))) {
      f.push(F('warn', 'Signature uses an XPath transform',
        'XPath transforms let a signature stay valid while the document changes shape around it, ' +
        'which is exactly the property wrapping attacks need. SAML profiles expect enveloped ' +
        'signature plus canonicalization and nothing else.',
        'Reject signatures with XPath transforms.', 'SAML 2.0 Core §5.4.4'));
    }
    if (transforms.length && !transforms.some(a => /enveloped-signature/i.test(a))) {
      f.push(F('note', 'No enveloped-signature transform',
        'An enveloped SAML signature normally lists the enveloped-signature transform so the ' +
        'signature value is excluded from its own digest. Without it, verification recomputes ' +
        'over bytes that include the signature, and rarely matches.',
        '', 'SAML 2.0 Core §5.4.4'));
    }
  }

  /* ---------------- signature and digest algorithms ---------------- */
  let weakSig = null, weakDig = null, hmacSig = null;
  for (const s of allSigs) {
    const sa = attr(el(s, 'SignatureMethod'), 'Algorithm') || '';
    const da = attr(el(s, 'DigestMethod'), 'Algorithm') || '';
    if (!weakSig && WEAK_SIG.test(sa)) weakSig = sa;
    if (!weakDig && WEAK_SIG.test(da)) weakDig = da;
    if (!hmacSig && /hmac/i.test(sa)) hmacSig = sa;
  }
  if (weakSig) {
    f.push(F('warn', 'Signature algorithm is ' + weakSig.split('#').pop(),
      'SHA-1 is retired for signatures. Plenty of deployments still run it because the other side ' +
      'never upgraded, and it is worth knowing which side that is.',
      'Move to rsa-sha256.', 'NIST SP 800-131A'));
  }
  if (weakDig) {
    f.push(F('warn', 'Digest algorithm is ' + weakDig.split('#').pop(),
      'A SHA-1 digest weakens the signature regardless of the signature algorithm above it.',
      'Move to sha256.', 'NIST SP 800-131A'));
  }
  if (hmacSig) {
    f.push(F('warn', 'HMAC-signed SAML (' + hmacSig.split('#').pop() + ')',
      'The verification key is the signing key, so every service provider that can verify this ' +
      'assertion can also mint one. Federation across a trust boundary needs an asymmetric signature.',
      'Use an RSA or ECDSA signature algorithm.', 'SAML 2.0 Core §5'));
  }
  if (allSigs.length && !weakSig && !weakDig) {
    f.push(F('ok', 'Signature and digest algorithms are current', ''));
  }

  /* ---------------- who this is for ---------------- */
  const audiences = els(root, 'Audience').map(a => a.textContent.trim()).filter(Boolean);
  const hasRestriction = els(root, 'AudienceRestriction').length > 0;
  if (assertions.length && !hasRestriction && !encAssertions.length) {
    f.push(F('critical', 'No AudienceRestriction',
      'Nothing scopes this assertion to one service provider. Any SP that trusts the same identity ' +
      'provider will accept it, so a malicious or compromised SP can replay it elsewhere.',
      'Add an AudienceRestriction and check it against your own entity ID.', 'SAML 2.0 Core §2.5.1.4'));
  } else if (audiences.length) {
    f.push(F('ok', 'Audience: ' + audiences.join(', '), ''));
  }

  const dest = attr(root, 'Destination');
  if (isResponse && !dest) {
    f.push(F('warn', 'No Destination attribute',
      'The response does not say where it was meant to be delivered, so it cannot be detected when ' +
      'it is delivered somewhere else.',
      'Set Destination and compare it to your own ACS URL.', 'SAML 2.0 Core §3.2.2'));
  }

  if (isResponse && !attr(root, 'InResponseTo')) {
    f.push(F('note', 'No InResponseTo, so this is IdP-initiated',
      'There is no request to correlate against, which means no protection against an attacker ' +
      'submitting a captured assertion to your ACS endpoint in a victim\'s browser.',
      'Prefer SP-initiated sign-on. If you must accept IdP-initiated, be strict about replay.',
      'SAML 2.0 Core §3.2.2'));
  }

  /* ---------------- validity windows ---------------- */
  const conds = el(root, 'Conditions');
  if (plainAssertions.length && !conds) {
    f.push(F('critical', 'Assertion has no Conditions element',
      'No validity window at all, so the assertion never goes stale and a captured one works forever.',
      'Emit NotBefore and NotOnOrAfter.', 'SAML 2.0 Core §2.5'));
  } else if (conds) {
    const nb = attr(conds, 'NotBefore'), na = attr(conds, 'NotOnOrAfter');
    if (!na) {
      f.push(F('critical', 'Conditions has no NotOnOrAfter',
        'The assertion does not expire.', 'Set a window of minutes.', 'SAML 2.0 Core §2.5.1.2'));
    } else {
      const end = samlInstant(na, f, 'Conditions NotOnOrAfter');
      const start = nb ? samlInstant(nb, f, 'Conditions NotBefore') : null;
      if (!isNaN(end)) {
        const remaining = (end - now * 1000) / 1000;
        if (remaining < 0) {
          f.push(F('note', 'Assertion expired ' + secondsToHuman(-remaining) + ' ago', ''));
        } else {
          f.push(F('ok', 'Assertion valid for another ' + secondsToHuman(remaining), ''));
        }
        if (start && !isNaN(start)) {
          const life = (end - start) / 1000;
          if (life > 3600) {
            f.push(F('warn', 'Validity window is ' + secondsToHuman(life),
              'A SAML assertion is a single-use sign-on artifact. A window this wide gives a captured ' +
              'assertion a long useful life.',
              'Five minutes is typical. Widen only as far as your clock skew genuinely requires.'));
          } else {
            f.push(F('ok', 'Validity window is ' + secondsToHuman(life), ''));
          }
        }
      }
    }
  }

  /* ---------------- subject confirmation, where bearer replay is bounded ---------------- */
  const scd = el(root, 'SubjectConfirmationData');
  const scMethod = String(attr(el(root, 'SubjectConfirmation'), 'Method') || '');
  if (plainAssertions.length && scd) {
    if (!attr(scd, 'Recipient')) {
      f.push(F('warn', 'SubjectConfirmationData has no Recipient',
        'Nothing states which endpoint may consume this, which is the per-assertion version of the ' +
        'Destination check.', '', 'SAML 2.0 Core §2.4.1.2'));
    }
    if (/cm:bearer/i.test(scMethod) || !scMethod) {
      if (!attr(scd, 'NotOnOrAfter')) {
        f.push(F('warn', 'SubjectConfirmationData has no NotOnOrAfter',
          'For a bearer assertion this attribute, not the Conditions window, is what bounds how ' +
          'long a captured assertion can be replayed to the ACS.',
          'Set it a few minutes out, alongside Recipient and InResponseTo.',
          'SAML 2.0 Profiles §4.1.4.2'));
      } else {
        const scdEnd = samlInstant(attr(scd, 'NotOnOrAfter'), f, 'SubjectConfirmationData NotOnOrAfter');
        if (!isNaN(scdEnd) && (scdEnd - now * 1000) / 1000 > 3600) {
          f.push(F('warn', 'Bearer confirmation is valid for another ' +
            secondsToHuman((scdEnd - now * 1000) / 1000),
            'This is the replay window for presenting the assertion to the ACS, and it is normally ' +
            'minutes, not hours.',
            'Shorten SubjectConfirmationData NotOnOrAfter.', 'SAML 2.0 Profiles §4.1.4.2'));
        }
      }
      if (isResponse && attr(root, 'InResponseTo') && !attr(scd, 'InResponseTo')) {
        f.push(F('warn', 'Response has InResponseTo but SubjectConfirmationData does not',
          'The response correlates to a request and the assertion inside it does not, so an ' +
          'assertion lifted from one exchange can ride inside another. Both layers carry it for ' +
          'a reason.',
          'Have the identity provider stamp InResponseTo on the SubjectConfirmationData too.',
          'SAML 2.0 Profiles §4.1.4.2'));
      }
    }
    if (scMethod && !/cm:(bearer|holder-of-key|sender-vouches)/i.test(scMethod)) {
      f.push(F('note', 'SubjectConfirmation method is unrecognised: ' + scMethod, '', ''));
    }
  }

  /* ---------------- the ACS URL ----------------
     Destination and Recipient should both name the same endpoint: your ACS.
     This is the single most common cause of a SAML login that fails with
     nothing useful in the log, and it is almost always cosmetic, one trailing
     slash or one wrong scheme. authlint cannot know your configured ACS, but
     the response carries the value twice and the two copies have to agree. */
  const recip = scd && attr(scd, 'Recipient');
  const urlShape = u => {
    const t = String(u || '').trim();
    if (!t) return null;
    if (!/^https?:\/\//i.test(t)) return { bad: 'no scheme' };
    try {
      const p = new URL(t);
      return { url: p, canon: p.protocol.toLowerCase() + '//' + p.host.toLowerCase() +
                            p.pathname.replace(/\/+$/, '') + p.search };
    } catch (e) { return { bad: 'not a valid URL' }; }
  };
  for (const [label, raw] of [['Destination', dest], ['Recipient', recip]]) {
    if (!raw) continue;
    if (raw !== String(raw).trim()) {
      f.push(F('warn', label + ' has leading or trailing whitespace',
        'Service providers compare this against the configured ACS URL as a string, and the ' +
        'whitespace is invisible in every log you will read while trying to work out why.',
        'Trim the value in the identity provider configuration.', 'SAML 2.0 Core §3.2.2'));
    }
    const sh = urlShape(raw);
    if (sh && sh.bad) {
      f.push(F('critical', label + ' is not an absolute URL (' + sh.bad + ')',
        'It has to be an absolute URI. A bare host or path will never match the ACS URL the ' +
        'service provider has configured, so sign-on fails before anything is validated.',
        'Set ' + label + ' to the full https URL of the assertion consumer service.',
        'SAML 2.0 Core §3.2.2'));
    } else if (sh && sh.url && sh.url.protocol === 'http:') {
      f.push(F('critical', label + ' is http, not https',
        'The assertion travels through the browser to this endpoint. Over http it is readable and ' +
        'replayable by anything on the path.',
        'Use https for the assertion consumer service.', 'SAML 2.0 Core §3.2.2'));
    }
  }
  if (dest && recip) {
    const a = urlShape(dest), b = urlShape(recip);
    if (a && b && a.canon && b.canon) {
      if (a.canon !== b.canon) {
        const sameHost = a.url.host.toLowerCase() === b.url.host.toLowerCase();
        f.push(F('critical', 'Destination and Recipient do not point at the same endpoint',
          'The response says it was issued for ' + dest.trim() + ' and the assertion says it may ' +
          'only be consumed at ' + String(recip).trim() + '. ' + (sameHost
            ? 'The paths differ, so one of the two is configured against a stale endpoint.'
            : 'They are different hosts, which is what a redirected or replayed assertion looks like.'),
          'Make both match the ACS URL the service provider has configured, exactly.',
          'SAML 2.0 Core §3.2.2 and §2.4.1.2'));
      } else if (String(dest).trim() !== String(recip).trim()) {
        f.push(F('warn', 'Destination and Recipient differ only in formatting',
          'They resolve to the same endpoint, but the strings are not identical: ' +
          String(dest).trim() + ' against ' + String(recip).trim() + '. Most service providers ' +
          'compare the ACS URL as a string, so a trailing slash or an explicit :443 is enough to ' +
          'fail the match while looking correct to a human.',
          'Make both byte-identical to the configured ACS URL.',
          'SAML 2.0 Core §3.2.2 and §2.4.1.2'));
      } else {
        f.push(F('ok', 'Destination and Recipient agree', ''));
      }
    }
  }

  /* ---------------- the subject ---------------- */
  const nameId = el(root, 'NameID');
  if (nameId) {
    const fmt = String(attr(nameId, 'Format') || '').split(':').pop();
    const val = nameId.textContent.trim();
    if (/emailAddress/i.test(fmt) || looksLikeEmail(val)) {
      f.push(F('warn', 'NameID is an email address',
        'Email addresses get changed on marriage and reissued after someone leaves. Either the ' +
        'account is orphaned or the next holder inherits it.',
        'Federate on an opaque immutable identifier and carry the email as an attribute.',
        'SAML 2.0 Core §8.3'));
    } else if (/transient/i.test(fmt)) {
      f.push(F('note', 'NameID format is transient',
        'A new identifier every sign-on. Correct for privacy, and it means the service provider ' +
        'cannot link this session to a stored account unless an attribute does it.', '', 'SAML 2.0 Core §8.3.8'));
    } else if (/unspecified/i.test(fmt)) {
      f.push(F('note', 'NameID format is unspecified',
        'Both sides are guessing at what the value means, which works right up until the identity ' +
        'provider changes it.', 'Agree a format explicitly.', 'SAML 2.0 Core §8.3.1'));
    } else if (/persistent/i.test(fmt)) {
      f.push(F('ok', 'NameID format is persistent', ''));
    }
  }

  const acr = el(root, 'AuthnContextClassRef');
  if (acr) {
    const v = acr.textContent.trim().split(':').pop();
    if (/^(Password|unspecified|PasswordProtectedTransport)$/i.test(v)) {
      f.push(F('note', 'AuthnContext is ' + v,
        'The assertion is telling you a password was used. If you rely on the identity provider for ' +
        'multi-factor, this is where you would see it, and it is not here.',
        'Request and enforce a stronger context if MFA is a requirement.', 'SAML 2.0 Core §2.7.2.2'));
    } else {
      f.push(F('ok', 'AuthnContext: ' + v, ''));
    }
  }

  /* ---------------- what is being carried ---------------- */
  const attrs = els(root, 'Attribute').map(a => attr(a, 'Name') || attr(a, 'FriendlyName')).filter(Boolean);
  if (attrs.length && !encAssertions.length) {
    const pii = attrs.filter(n => /mail|phone|name|address|birth|ssn|nino|employee/i.test(n));
    if (pii.length) {
      f.push(F('note', attrs.length + ' attributes in the clear, including ' + pii.slice(0, 4).join(', '),
        'The assertion is signed, not encrypted. It passes through the user\'s browser and lands in ' +
        'any logs on the way.',
        'Use EncryptedAssertion if the attributes are sensitive.', 'SAML 2.0 Core §2.3.4'));
    }
  }

  checkSamlCerts(root, now, f);

  f.push(F('note', 'authlint did not verify the signature',
    'The checks above are about structure and content, including whether each signature points at ' +
    'the element it lives in. Whether a signature actually validates against a trusted key is a ' +
    'separate question, and it needs the key.',
    'Validate in your own code, against the certificate you configured, over the element you consume.'));

  return sortFindings(f);
}

/* Certificate expiry, shared between responses and requests. */
function checkSamlCerts(root, now, f) {
  const certs = els(root, 'X509Certificate');
  for (const c of certs.slice(0, 3)) {
    const v = certValidity(c.textContent);
    if (!v) continue;
    if (v.notBefore && now * 1000 < v.notBefore.getTime()) {
      f.push(F('warn', 'Signing certificate is not valid yet (notBefore is in the future)',
        'Validators that check the window are rejecting it right now, and the failure reads as a ' +
        'bad signature rather than a date problem.', 'Check the rotation that minted it.'));
    }
    const days = (v.notAfter - now * 1000) / 86400000;
    if (days < 0) {
      f.push(F('critical', 'Signing certificate expired ' + Math.abs(Math.round(days)) + ' days ago',
        'Every service provider that checks expiry is already rejecting this.', 'Rotate it.'));
    } else if (days < 45) {
      f.push(F('warn', 'Signing certificate expires in ' + Math.round(days) + ' days',
        'Certificate expiry is the most common cause of a federation outage, and the failure is total ' +
        'rather than gradual.', 'Schedule the rotation and tell the other side now.'));
    } else {
      f.push(F('ok', 'Signing certificate valid for another ' + Math.round(days) + ' days', ''));
    }
    break;
  }
}

/* ============================== AUTHN REQUEST ==============================
   An AuthnRequest is not a response, and running response checks over it
   produces criticals about missing signatures on a message that is commonly
   and legally unsigned. What matters here is different: where the request
   asks the assertion to be sent, and what it asks for. */
function checkSamlAuthnRequest(x, now) {
  const f = [];
  const root = x.doc.documentElement;

  const sigs = els(root, 'Signature');
  if (sigs.length) {
    f.push(F('ok', 'Request is signed', ''));
  } else {
    f.push(F('note', 'Request is not signed',
      'Legal and common: whether the identity provider requires signed requests is set in metadata ' +
      '(AuthnRequestsSigned). Unsigned requests mean anyone can start a flow with parameters of ' +
      'their choosing, which matters most when the request names its own ACS URL.',
      '', 'SAML 2.0 Metadata §2.4.4'));
  }

  const acs = attr(root, 'AssertionConsumerServiceURL');
  if (acs) {
    if (/^http:/i.test(acs)) {
      f.push(F('critical', 'AssertionConsumerServiceURL is plaintext http: ' + acs,
        'The assertion would be delivered over a channel anyone on the path can read.',
        'Use https.', 'SAML 2.0 Core §3.4.1'));
    }
    f.push(F(sigs.length ? 'note' : 'warn', 'The request names its own ACS URL: ' + acs,
      'The identity provider must match this against the URLs registered in metadata before ' +
      'honouring it. An IdP that trusts it as sent will deliver the assertion wherever a forged ' +
      'request points' + (sigs.length ? '.' : ', and this request is unsigned.'),
      'Confirm the IdP validates ACS URLs against metadata.', 'SAML 2.0 Core §3.4.1'));
  }

  const dest = attr(root, 'Destination');
  if (dest && /^http:/i.test(dest)) {
    f.push(F('critical', 'Destination is plaintext http: ' + dest, '',
      'Use https.', 'SAML 2.0 Core §3.4.1'));
  }

  if (!attr(root, 'ID')) {
    f.push(F('warn', 'Request has no ID',
      'The response\'s InResponseTo has nothing to correlate against, so the service provider ' +
      'cannot tie the answer to this question.', 'Emit a unique ID per request.', 'SAML 2.0 Core §3.4.1'));
  }
  samlInstant(attr(root, 'IssueInstant'), f, 'IssueInstant');

  if (String(attr(root, 'ForceAuthn')).toLowerCase() === 'true') {
    f.push(F('note', 'ForceAuthn is true',
      'The IdP is asked to reauthenticate the user rather than reuse the session. Deliberate for ' +
      'step-up moments; as a default it turns SSO off.', '', 'SAML 2.0 Core §3.4.1'));
  }
  if (String(attr(root, 'IsPassive')).toLowerCase() === 'true') {
    f.push(F('note', 'IsPassive is true',
      'The IdP may not interact with the user, so this only succeeds for an existing session.', '',
      'SAML 2.0 Core §3.4.1'));
  }

  const nip = el(root, 'NameIDPolicy');
  if (nip) {
    const fmt = String(attr(nip, 'Format') || '');
    if (/emailAddress/i.test(fmt)) {
      f.push(F('warn', 'NameIDPolicy requests email-address identifiers',
        'The service provider is asking to federate on a mutable, reassignable value.',
        'Request persistent identifiers and carry the email as an attribute.', 'SAML 2.0 Core §8.3'));
    }
    if (String(attr(nip, 'AllowCreate')).toLowerCase() === 'true') {
      f.push(F('note', 'NameIDPolicy AllowCreate is true',
        'The IdP may mint a new identifier for a user it has not federated before. Normal for ' +
        'just-in-time provisioning; worth knowing it is on.', '', 'SAML 2.0 Core §3.4.1.1'));
    }
  }

  if (sigs.length) {
    f.push(F('note', 'authlint did not verify the signature',
      'Whether it validates against the service provider\'s registered certificate needs the key.',
      ''));
  }
  return sortFindings(f);
}

/* ============================== LOGOUT MESSAGES ==============================
   Small checks, mostly about what an unsigned or unbounded logout message
   permits. These were previously mislabelled as responses and graded with
   response rules, which produced "anyone can log in as anyone" findings on a
   message that logs people out. */
function checkSamlLogout(x, now) {
  const f = [];
  const root = x.doc.documentElement;
  const isRequest = /LogoutRequest$/i.test(root.localName);

  const sigs = els(root, 'Signature');
  if (sigs.length) {
    f.push(F('ok', root.localName + ' is signed', ''));
  } else if (isRequest) {
    f.push(F('warn', 'LogoutRequest is not signed',
      'A forged logout is a denial of service: anyone who can reach the endpoint ends the ' +
      'victim\'s sessions. Most deployments require signatures on single logout for exactly ' +
      'this reason.',
      'Sign logout messages and require signatures on both sides.', 'SAML 2.0 Core §3.7'));
  } else {
    f.push(F('note', 'LogoutResponse is not signed', '', '', 'SAML 2.0 Core §3.7'));
  }

  const dest = attr(root, 'Destination');
  if (dest && /^http:/i.test(dest)) {
    f.push(F('critical', 'Destination is plaintext http: ' + dest, '', 'Use https.', 'SAML 2.0 Core §3.7'));
  }

  if (isRequest) {
    const nameId = el(root, 'NameID');
    if (nameId && looksLikeEmail(nameId.textContent.trim())) {
      f.push(F('note', 'Logout names the principal by email address',
        'The same mutability problem as an email NameID at sign-on, and one more place the ' +
        'address lands in logs.', '', 'SAML 2.0 Core §8.3'));
    }
    if (!el(root, 'SessionIndex')) {
      f.push(F('note', 'No SessionIndex',
        'Without it the IdP can only end every session for the principal, not the one session ' +
        'this request came from.', '', 'SAML 2.0 Core §3.7.1'));
    }
    const na = attr(root, 'NotOnOrAfter');
    if (na) samlInstant(na, f, 'NotOnOrAfter');
  }

  const sc = el(root, 'StatusCode');
  if (sc && !isRequest) {
    const v = attr(sc, 'Value') || '';
    f.push(F(/:Success$/i.test(v) ? 'ok' : 'note', 'Status: ' + v.split(':').pop(), ''));
  }

  return sortFindings(f);
}

function checkSamlMetadata(x, now) {
  const f = [];
  const root = x.doc.documentElement;

  const validUntil = attr(root, 'validUntil');
  if (validUntil) {
    const d = samlInstant(validUntil, f, 'validUntil');
    if (!isNaN(d)) {
      const days = (d - now * 1000) / 86400000;
      if (days < 0) {
        f.push(F('critical', 'Metadata expired ' + Math.abs(Math.round(days)) + ' days ago',
          'Implementations that honour validUntil will refuse to load this.', 'Republish it.'));
      } else if (days < 30) {
        f.push(F('warn', 'Metadata expires in ' + Math.round(days) + ' days', '', 'Republish before it lapses.'));
      }
    }
  }

  const metaSigned = els(root, 'Signature').some(s => s.parentNode === root);
  if (!metaSigned) {
    f.push(F('note', 'Metadata is not signed',
      'Whoever serves this document chooses the endpoints and keys the other side will trust. ' +
      'HTTPS protects it in transit; a signature with a pinned metadata key protects it from the ' +
      'server itself, which is why the large federations require one.',
      'Sign metadata and pin the signing key out of band.', 'SAML 2.0 Metadata §3'));
  } else {
    f.push(F('ok', 'Metadata is signed', ''));
  }

  for (const sso of els(root, 'SPSSODescriptor')) {
    if (String(attr(sso, 'WantAssertionsSigned')).toLowerCase() === 'false') {
      f.push(F('critical', 'WantAssertionsSigned is false',
        'This service provider is publishing that it will accept unsigned assertions. Anyone can ' +
        'write one.', 'Set it to true and enforce it in the implementation, not just the metadata.',
        'SAML 2.0 Metadata §2.4.4'));
    } else if (String(attr(sso, 'WantAssertionsSigned')).toLowerCase() === 'true') {
      f.push(F('ok', 'WantAssertionsSigned is true', ''));
    }
    if (String(attr(sso, 'AuthnRequestsSigned')).toLowerCase() !== 'true') {
      f.push(F('note', 'AuthnRequestsSigned is not true',
        'Requests are unsigned, so the identity provider cannot confirm which service provider asked.',
        '', 'SAML 2.0 Metadata §2.4.4'));
    }
  }

  const endpoints = els(root, 'AssertionConsumerService')
    .concat(els(root, 'SingleSignOnService'))
    .concat(els(root, 'SingleLogoutService'));
  const plain = endpoints.map(e => attr(e, 'Location')).filter(l => l && /^http:/i.test(l));
  if (plain.length) {
    f.push(F('critical', plain.length + ' endpoint(s) on plaintext http',
      'Assertions delivered over a channel anyone on the path can read and rewrite.',
      'Publish https endpoints only.', 'SAML 2.0 Security §4.1'));
  } else if (endpoints.length) {
    f.push(F('ok', 'All ' + endpoints.length + ' endpoints are https', ''));
  }

  const certs = els(root, 'X509Certificate');
  if (!certs.length) {
    f.push(F('warn', 'No certificate in the metadata',
      'Nothing here to validate signatures against, so the other side has to get the key some other ' +
      'way, and "some other way" is usually email.'));
  }
  let i = 0;
  for (const c of certs) {
    const v = certValidity(c.textContent);
    if (!v) { f.push(F('note', 'A certificate could not be parsed', '')); continue; }
    const label = 'Certificate ' + (++i) + ' of ' + certs.length;
    if (v.notBefore && now * 1000 < v.notBefore.getTime()) {
      f.push(F('warn', label + ' is not valid yet (notBefore is in the future)',
        'Published ahead of its own validity. Verifiers that check the window reject it until then.',
        ''));
    }
    const days = (v.notAfter - now * 1000) / 86400000;
    if (days < 0) {
      f.push(F('critical', label + ' expired ' + Math.abs(Math.round(days)) + ' days ago',
        'If this is the active signing certificate, the federation is down.', 'Rotate it.'));
    } else if (days < 45) {
      f.push(F('warn', label + ' expires in ' + Math.round(days) + ' days',
        'Tell the other side now. Metadata exchange takes longer than anyone plans for.', 'Rotate it.'));
    } else {
      f.push(F('ok', label + ' valid for another ' + Math.round(days) + ' days', ''));
    }
  }
  if (certs.length > 1) {
    f.push(F('ok', certs.length + ' certificates published, which is what a clean rotation looks like', ''));
  }

  return sortFindings(f);
}
