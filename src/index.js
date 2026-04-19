const { app } = require('@azure/functions');
const crypto = require('crypto');

// ============================================================
//  Tech-Net signing service
//  Two HTTP-triggered endpoints:
//    POST /api/sign    -> returns signed token
//    POST /api/verify  -> verifies a token, returns components
//
//  Secret is read from app setting TECHNET_SIGNING_SECRET
//  (which is wired to a Key Vault reference in production).
//
//  Token format:
//    base64url( payload ) + "." + base64url( signature )
//  where payload = JSON.stringify({ ticketId, expiry, nonce })
//  and   signature = HMAC-SHA256(payload, secret)
// ============================================================

function getSecret() {
  const s = process.env.TECHNET_SIGNING_SECRET;
  if (!s || s.length < 32) {
    throw new Error('Signing secret not configured (TECHNET_SIGNING_SECRET)');
  }
  return s;
}

function b64urlEncode(bufOrStr) {
  const buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr, 'utf8');
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecodeToString(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const base64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(base64, 'base64').toString('utf8');
}

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function sign(payloadObj) {
  const payloadJson = JSON.stringify(payloadObj);
  const payloadEncoded = b64urlEncode(payloadJson);
  const sig = crypto.createHmac('sha256', getSecret())
    .update(payloadEncoded)
    .digest();
  const sigEncoded = b64urlEncode(sig);
  return payloadEncoded + '.' + sigEncoded;
}

function verify(token) {
  if (typeof token !== 'string' || token.indexOf('.') < 1) {
    return { valid: false, reason: 'malformed' };
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'malformed' };
  }
  const [payloadEncoded, sigEncoded] = parts;

  const expectedSig = crypto.createHmac('sha256', getSecret())
    .update(payloadEncoded)
    .digest();
  const expectedSigEncoded = b64urlEncode(expectedSig);

  if (!timingSafeEqualStr(sigEncoded, expectedSigEncoded)) {
    return { valid: false, reason: 'bad_signature' };
  }

  let payload;
  try {
    payload = JSON.parse(b64urlDecodeToString(payloadEncoded));
  } catch (e) {
    return { valid: false, reason: 'malformed' };
  }

  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'malformed' };
  }
  if (!payload.ticketId || !payload.expiry || !payload.nonce) {
    return { valid: false, reason: 'missing_fields' };
  }

  const now = Date.now();
  const expiry = Date.parse(payload.expiry);
  if (!Number.isFinite(expiry)) {
    return { valid: false, reason: 'bad_expiry' };
  }
  if (expiry < now) {
    return { valid: false, reason: 'expired' };
  }

  return {
    valid: true,
    ticketId: payload.ticketId,
    expiry: payload.expiry,
    nonce: payload.nonce
  };
}

// ------------------------------------------------------------
//  POST /api/sign
//  Body: { ticketId, expiryDays?, nonce? }
//  Returns: { token, ticketId, expiry, nonce }
// ------------------------------------------------------------
app.http('sign', {
  methods: ['POST'],
  authLevel: 'function',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const ticketId = body?.ticketId;
      if (!ticketId && ticketId !== 0) {
        return { status: 400, jsonBody: { error: 'ticketId required' } };
      }

      const expiryDays = Number(body?.expiryDays ?? 7);
      const expiry = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString();
      const nonce = body?.nonce || crypto.randomBytes(16).toString('hex');

      const token = sign({ ticketId: String(ticketId), expiry, nonce });

      return {
        status: 200,
        jsonBody: { token, ticketId: String(ticketId), expiry, nonce }
      };
    } catch (err) {
      context.error('sign error', err);
      return { status: 500, jsonBody: { error: 'sign_failed', detail: err.message } };
    }
  }
});

// ------------------------------------------------------------
//  POST /api/verify
//  Body: { token }
//  Returns on valid:   { valid: true, ticketId, expiry, nonce }
//  Returns on invalid: { valid: false, reason }
// ------------------------------------------------------------
app.http('verify', {
  methods: ['POST'],
  authLevel: 'function',
  handler: async (request, context) => {
    try {
      const body = await request.json();
      const token = body?.token;
      if (!token) {
        return { status: 400, jsonBody: { valid: false, reason: 'missing_token' } };
      }
      const result = verify(token);
      return { status: 200, jsonBody: result };
    } catch (err) {
      context.error('verify error', err);
      return { status: 500, jsonBody: { valid: false, reason: 'verify_error', detail: err.message } };
    }
  }
});
