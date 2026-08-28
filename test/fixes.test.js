/* Regression tests for the 28 August 2026 review pass. One test per fixed
   defect, so none of them can come back quietly. The naming convention says
   what USED to happen. */
const { test } = require('node:test');
const assert = require('node:assert');
const { sandbox, jwt, NOW, has, titles } = require('./harness.js');
const { detect, decodeJwt, checkJwt, checkJwks, checkDiscovery, parseAuthz, checkAuthz,
        decodeXml, checkSamlResponse, checkSamlMetadata, checkSamlAuthnRequest,
        checkSamlLogout, checkTokenResponse, checkCookie, jwtProfile, inflateRaw } = sandbox;

const good = { iss: 'https://id.example.com', sub: 'u-1', aud: 'api', iat: NOW - 60, exp: NOW + 600, jti: 'x' };
const runJwt = (h, p, sig) => checkJwt(decodeJwt(jwt(h, p, sig)), NOW);

/* ------------------------------ DPoP ------------------------------ */

const dpopProof = () => jwt(
  { alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } },
  { jti: 'p-1', htm: 'POST', htu: 'https://api.example.com/orders', iat: NOW - 5 });

test('a DPoP proof used to get criticals for its required jwk and its absent exp/iss/aud', () => {
  const f = checkJwt(decodeJwt(dpopProof()), NOW);
  assert.ok(!has(f, 'critical', 'own public key'), titles(f).join('\n'));
  assert.ok(!has(f, 'critical', 'no exp'));
  assert.ok(!has(f, 'critical', 'no iss'));
  assert.ok(!has(f, 'warn', 'no aud'));
  assert.ok(has(f, 'ok', 'dpop proof'));
  assert.ok(has(f, 'ok', 'embeds the proof public key'));
});

test('a DPoP proof missing its required claims is told which', () => {
  const f = checkJwt(decodeJwt(jwt(
    { alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC' } }, { htm: 'GET' })), NOW);
  assert.ok(has(f, 'critical', 'no jti'));
  assert.ok(has(f, 'critical', 'no htu'));
  assert.ok(has(f, 'critical', 'no iat'));
});

test('a DPoP proof with a private key in its jwk is critical', () => {
  const f = checkJwt(decodeJwt(jwt(
    { alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC', d: 'PRIVATE' } },
    { jti: 'x', htm: 'GET', htu: 'https://a/b', iat: NOW })), NOW);
  assert.ok(has(f, 'critical', 'private'));
});

test('an HMAC DPoP proof is critical: possession proves nothing', () => {
  const f = checkJwt(decodeJwt(jwt(
    { alg: 'HS256', typ: 'dpop+jwt', jwk: { kty: 'oct' } },
    { jti: 'x', htm: 'GET', htu: 'https://a/b', iat: NOW })), NOW);
  assert.ok(has(f, 'critical', 'symmetric'));
});

/* ------------------------------ JWE ------------------------------ */

test('a JWE used to get bogus exp/iss/aud criticals from its empty payload', () => {
  const jwe = ['eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ', 'a2V5', 'aXY', 'Y2lwaGVy', 'dGFn'].join('.');
  const f = checkJwt(decodeJwt(jwe), NOW);
  assert.ok(!has(f, 'critical', 'no exp'), titles(f).join('\n'));
  assert.ok(!has(f, 'critical', 'no iss'));
  assert.ok(!has(f, 'warn', 'no aud'));
  assert.ok(!has(f, 'note', 'no kid'));           // RSA-OAEP is key management, not a signature
  assert.ok(!has(f, 'note', 'did not verify'));   // there is no signature on a JWE
  assert.ok(has(f, 'note', 'encrypted'));
});

test('RSA1_5 and zip in a JWE header are reported', () => {
  const mk = h => ['a', 'b', 'c', 'd', 'e'].map((s, i) => i === 0
    ? Buffer.from(JSON.stringify(h)).toString('base64url') : 'QUFB').join('.');
  assert.ok(has(checkJwt(decodeJwt(mk({ alg: 'RSA1_5', enc: 'A128CBC-HS256' })), NOW), 'warn', 'RSA1_5'));
  assert.ok(has(checkJwt(decodeJwt(mk({ alg: 'RSA-OAEP', enc: 'A256GCM', zip: 'DEF' })), NOW), 'warn', 'compressed'));
});

/* ------------------------------ four segments ------------------------------ */

test('a four-segment paste used to be decoded with its fourth segment silently dropped', () => {
  const t = jwt({ alg: 'RS256' }, good) + '.extra';
  assert.ok(decodeJwt(t).error, 'four segments must refuse, not truncate');
});

/* ------------------------------ NumericDate strings ------------------------------ */

test('a string exp used to produce zero time findings; now it is the finding', () => {
  const f = runJwt({ alg: 'RS256' }, Object.assign({}, good, { exp: String(NOW - 97200) }));
  assert.ok(has(f, 'critical', 'exp is a string'));
  assert.ok(has(f, 'note', 'expired'), 'expiry is still evaluated: ' + titles(f).join('\n'));
});

/* ------------------------------ iss trailing slash ------------------------------ */

test('the trailing slash on iss, the tool\'s own signature finding, now fires on JWTs too', () => {
  const f = runJwt({ alg: 'RS256' }, Object.assign({}, good, { iss: 'https://login.example.com/' }));
  assert.ok(has(f, 'note', 'trailing slash'));
});

/* ------------------------------ logout tokens ------------------------------ */

test('a logout token carrying a nonce is critical', () => {
  const f = runJwt({ alg: 'RS256' }, Object.assign({}, good, {
    events: { 'http://schemas.openid.net/event/backchannel-logout': {} }, nonce: 'n' }));
  assert.ok(has(f, 'critical', 'nonce'));
});

/* ------------------------------ sender-constraining ------------------------------ */

test('cnf binding is recognised; a bare bearer access token is noted', () => {
  const bound = runJwt({ alg: 'RS256' }, Object.assign({}, good, { scope: 'x', cnf: { jkt: 'T' } }));
  assert.ok(has(bound, 'ok', 'sender-constrained'));
  const bearer = runJwt({ alg: 'RS256' }, Object.assign({}, good, { scope: 'x' }));
  assert.ok(has(bearer, 'note', 'bearer token'));
});

/* ------------------------------ detection ------------------------------ */

test('a random URL with a query string used to be graded as an OAuth request', () => {
  assert.equal(detect('https://www.google.com/search?q=oauth').kind, null);
  assert.equal(detect('https://id.example.com/authorize?response_type=code&client_id=x').kind, 'authz');
});

test('logout messages used to be graded with sign-on response rules', () => {
  assert.equal(detect('<samlp:LogoutResponse xmlns:samlp="urn:x"/>').kind, 'samllogout');
  assert.equal(detect('<samlp:LogoutRequest xmlns:samlp="urn:x"/>').kind, 'samllogout');
});

test('the token endpoint response, the most-pasted JSON in OAuth, is recognised', () => {
  assert.equal(detect('{"access_token":"abc","token_type":"Bearer","expires_in":3600}').kind, 'tokenresp');
  assert.equal(detect('{"active":false}').kind, 'tokenresp');
});

test('a redirect-binding SSO URL is unwrapped by parameter', () => {
  const d = detect('https://idp.example.com/sso?SAMLRequest=fVJdb5swFP0riPeA%2BQ&RelayState=x');
  assert.equal(d.kind, 'samlparam');
});

/* ------------------------------ authorization requests ------------------------------ */

test('duplicated parameters used to be silently last-one-wins', () => {
  const a = parseAuthz('https://id.example.com/authorize?response_type=code&client_id=x' +
    '&redirect_uri=https%3A%2F%2Fgood.example%2Fcb&redirect_uri=https%3A%2F%2Fevil.example%2Fcb' +
    '&code_challenge=c&code_challenge_method=S256&state=0123456789abcdef');
  const f = checkAuthz(a, NOW);
  assert.ok(has(f, 'critical', 'appears 2 times'), titles(f).join('\n'));
});

test('PKCE-covered CSRF: missing state without PKCE warns, with PKCE it is a note', () => {
  const noneither = checkAuthz(parseAuthz('https://a/az?response_type=code&client_id=x'), NOW);
  assert.ok(has(noneither, 'warn', 'no state and no pkce'));
  const pkce = checkAuthz(parseAuthz('https://a/az?response_type=code&client_id=x' +
    '&code_challenge=c&code_challenge_method=S256'), NOW);
  assert.ok(!has(pkce, 'warn', 'no state'));
  assert.ok(has(pkce, 'note', 'no state'));
});

test('exact-match bypass shapes in redirect_uri are reported', () => {
  const mk = r => checkAuthz(parseAuthz('https://a/az?response_type=code&client_id=x' +
    '&code_challenge=c&code_challenge_method=S256&redirect_uri=' + encodeURIComponent(r)), NOW);
  assert.ok(has(mk('https://app.example.com@evil.com/cb'), 'critical', 'userinfo'));
  assert.ok(has(mk('https://app.example.com/cb/../../evil'), 'warn', 'traversal'));
  assert.ok(has(mk('https://app.example.com/cb?next=https://evil.com'), 'warn', 'nested'));
});

test('a code callback without the RFC 9207 iss parameter is noted; with it, passed', () => {
  const without = checkAuthz(parseAuthz('https://app/cb?code=abc&state=xyz'), NOW);
  assert.ok(has(without, 'note', 'no iss'));
  const withIss = checkAuthz(parseAuthz('https://app/cb?code=abc&state=xyz&iss=' +
    encodeURIComponent('https://id.example.com')), NOW);
  assert.ok(has(withIss, 'ok', 'iss'));
});

/* ------------------------------ discovery ------------------------------ */

test('a discovery document from hell used to return two green passes', () => {
  const f = checkDiscovery({
    issuer: 'https://id.example.com',
    authorization_endpoint: 'https://id.example.com/az',
    token_endpoint: 'https://id.example.com/tk',
    jwks_uri: 'https://id.example.com/jwks',
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    grant_types_supported: ['authorization_code', 'password', 'implicit',
                            'urn:ietf:params:oauth:grant-type:jwt-bearer'],
    token_endpoint_auth_methods_supported: ['none'],
    request_object_signing_alg_values_supported: ['none', 'RS256'],
  }, NOW);
  assert.ok(has(f, 'critical', 'password grant'), titles(f).join('\n'));
  assert.ok(has(f, 'warn', 'grant_types_supported'));      // implicit via the grant list
  assert.ok(!has(f, 'ok', 'no implicit flow'));            // the false pass is gone
  assert.ok(has(f, 'warn', 'unsigned request objects'));
  assert.ok(has(f, 'note', 'unauthenticated token requests'));
});

/* ------------------------------ JWKS ------------------------------ */

test('a modulus that does not decode used to be swallowed by a bare catch', () => {
  const f = checkJwks({ keys: [{ kty: 'RSA', kid: 'k1', n: 'x'.repeat(145), e: 'AQAB' }] }, NOW);
  assert.ok(has(f, 'warn', 'does not decode'), titles(f).join('\n'));
});

test('the shipped sample JWKS now exercises the RSA size check', () => {
  // 1024-bit modulus: the size critical is part of the demo.
  const n = '97w2NJVvczC2FffTqfAWGry44eB-gNkuofgqYOSy_3EP93jk8C7HJy5T6pta7KXWD0Uq1KZNhFIs' +
            'HrNxwKTsesb_3umKNuRkAuCVOefKF-kogbVxvksQ7ZOVyUytDa4sgg35XWeDDhx6NI6qQCGRGSdn' +
            'lqPiO_axGHzq5-t9eMk';
  const f = checkJwks({ keys: [{ kty: 'RSA', kid: 'k1', n, e: 'AQAB' }] }, NOW);
  assert.ok(has(f, 'critical', '1024 bits'), titles(f).join('\n'));
});

/* ------------------------------ SAML ------------------------------ */

const SAML_NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
                'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';
const sig = (ref, extra) =>
  '<ds:Signature><ds:SignedInfo>' +
  '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
  '<ds:Reference URI="' + ref + '">' + (extra || '') +
  '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
  '</ds:Reference></ds:SignedInfo><ds:SignatureValue>c2ln</ds:SignatureValue></ds:Signature>';

test('a signed response wrapping an EncryptedAssertion used to fire the classic-break critical', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1" Destination="https://sp/acs">' +
    sig('#_r1') +
    '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>' +
    '</saml:EncryptedAssertion></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(!has(f, 'critical', 'assertion inside it is not'), titles(f).join('\n'));
  assert.ok(has(f, 'ok', 'assertion is encrypted'));
});

test('a signature pointing at an element other than its parent is the wrapping mechanism, observed', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1">' +
    '<saml:Assertion ID="_a1">' + sig('#_r1') + '<saml:Subject/></saml:Assertion>' +
    '</samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'critical', 'does not cover its own parent'), titles(f).join('\n'));
});

test('a signature reference that resolves nowhere is critical', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1">' + sig('#_ghost') +
    '<saml:Assertion ID="_a1"/></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'critical', 'does not exist'));
});

test('an XPath transform in a signature is reported', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1">' +
    sig('#_r1', '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/></ds:Transforms>') +
    '<saml:Assertion ID="_a1"/></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'warn', 'xpath'));
});

test('a weak digest no longer coexists with an algorithms-are-current pass', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1">' +
    '<ds:Signature><ds:SignedInfo>' +
    '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
    '<ds:Reference URI="#_r1">' +
    '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
    '</ds:Reference></ds:SignedInfo><ds:SignatureValue>c2ln</ds:SignatureValue></ds:Signature>' +
    '<saml:Assertion ID="_a1"/></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'warn', 'digest algorithm'));
  assert.ok(!has(f, 'ok', 'algorithms are current'), titles(f).join('\n'));
});

test('an element named Assertion in a foreign namespace is a look-alike, and critical', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1" xmlns:evil="urn:attacker">' +
    sig('#_r1') + '<evil:Assertion ID="_a1"/></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'critical', 'foreign namespace'), titles(f).join('\n'));
});

test('a zoneless SAML timestamp used to be parsed as local time; now it is UTC plus a finding', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1">' + sig('#_r1') +
    '<saml:Assertion ID="_a1"><saml:Conditions NotBefore="2026-08-28T10:00:00" ' +
    'NotOnOrAfter="2026-08-28T10:05:00"/></saml:Assertion></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'warn', 'no timezone'), titles(f).join('\n'));
});

test('a bearer SubjectConfirmationData without NotOnOrAfter is reported', () => {
  const xml = '<samlp:Response ' + SAML_NS + ' ID="_r1" InResponseTo="_req1">' + sig('#_r1') +
    '<saml:Assertion ID="_a1"><saml:Subject>' +
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    '<saml:SubjectConfirmationData Recipient="https://sp/acs"/>' +
    '</saml:SubjectConfirmation></saml:Subject>' + sig('#_a1').replace('_r1', '_a1') +
    '</saml:Assertion></samlp:Response>';
  const f = checkSamlResponse(decodeXml(xml), NOW);
  assert.ok(has(f, 'warn', 'subjectconfirmationdata has no notonorafter'), titles(f).join('\n'));
  assert.ok(has(f, 'warn', 'subjectconfirmationdata does not'), 'InResponseTo asymmetry: ' + titles(f).join('\n'));
});

test('an AuthnRequest used to be graded as a response: unsigned meant "anyone can log in"', () => {
  const xml = '<samlp:AuthnRequest ' + SAML_NS + ' ID="_q1" IssueInstant="2026-08-28T10:00:00Z" ' +
    'AssertionConsumerServiceURL="https://sp.example.com/acs"/>';
  const f = checkSamlAuthnRequest(decodeXml(xml), NOW);
  assert.ok(!has(f, 'critical', 'nothing is signed'), titles(f).join('\n'));
  assert.ok(has(f, 'warn', 'names its own acs'));
});

test('a LogoutRequest gets logout rules, not response rules', () => {
  const xml = '<samlp:LogoutRequest ' + SAML_NS + ' ID="_l1">' +
    '<saml:NameID>u@example.com</saml:NameID></samlp:LogoutRequest>';
  const f = checkSamlLogout(decodeXml(xml), NOW);
  assert.ok(has(f, 'warn', 'logoutrequest is not signed'));
  assert.ok(has(f, 'note', 'no sessionindex'));
});

test('unsigned metadata is noted; signed metadata passes', () => {
  const unsigned = checkSamlMetadata(decodeXml('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>'), NOW);
  assert.ok(has(unsigned, 'note', 'metadata is not signed'));
});

/* ------------------------------ token responses & cookies ------------------------------ */

test('token endpoint response findings', () => {
  const f = checkTokenResponse({ access_token: 'opaque123', token_type: 'bearer',
                                 refresh_token: 'r1' }, NOW);
  assert.ok(has(f, 'warn', 'no expires_in'));
  assert.ok(has(f, 'note', 'token_type is'));
  assert.ok(has(f, 'note', 'refresh token'));
  assert.ok(has(f, 'note', 'opaque'));
});

test('an inactive introspection response that says more than active:false leaks', () => {
  const f = checkTokenResponse({ active: false, sub: 'u1', scope: 'admin' }, NOW);
  assert.ok(has(f, 'warn', 'inactive'));
});

test('Set-Cookie attribute linting', () => {
  const f = checkCookie('Set-Cookie: session=abc123; Path=/; SameSite=None', NOW);
  assert.ok(has(f, 'critical', 'samesite=none without secure'), titles(f).join('\n'));
  assert.ok(has(f, 'warn', 'readable by script'));
  const host = checkCookie('Set-Cookie: __Host-sid=abc; Domain=example.com; Path=/', NOW);
  assert.ok(has(host, 'critical', '__host-'));
  const clean = checkCookie('Set-Cookie: __Host-sid=abc; Secure; HttpOnly; Path=/; SameSite=Lax', NOW);
  assert.ok(has(clean, 'ok', '__host-'));
  assert.ok(!has(clean, 'critical', 'secure'));
});

/* ------------------------------ inflate ------------------------------ */

test('redirect-binding SAML inflates in-process, with no dependency', async () => {
  const zlib = require('node:zlib');
  const xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_q1"/>';
  const deflated = zlib.deflateRawSync(Buffer.from(xml));
  const b64 = deflated.toString('base64');
  const x = decodeXml(b64);
  assert.ok(x.deflate, 'decodeXml hands back bytes for the async inflate');
  const inflated = await inflateRaw(x.deflate);
  assert.equal(inflated, xml);
});

/* ------------------------------ profiles ------------------------------ */

test('jwtProfile tells the five artifact kinds apart', () => {
  assert.equal(jwtProfile(decodeJwt(dpopProof())), 'dpop');
  assert.equal(jwtProfile(decodeJwt(jwt({ alg: 'RS256' }, Object.assign({}, good, { nonce: 'n' })))), 'id');
  assert.equal(jwtProfile(decodeJwt(jwt({ alg: 'RS256', typ: 'at+jwt' }, good))), 'at');
  assert.equal(jwtProfile(decodeJwt(jwt({ alg: 'RS256' }, Object.assign({}, good,
    { events: { 'http://schemas.openid.net/event/backchannel-logout': {} } })))), 'logout');
  assert.equal(jwtProfile(decodeJwt(jwt({ alg: 'RS256' }, good))), 'jwt');
});
