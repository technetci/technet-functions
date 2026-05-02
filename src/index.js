const { app } = require('@azure/functions');
const crypto = require('crypto');

// =========================================================
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
//  where payload = JSON.stringify({ ticketId, expiry, nonce, sender? })
//  and   signature = HMAC-SHA256(payload, secret)
//
//  sender is optional on sign for backward compatibility, but when
//  supplied it is included in the HMAC payload so it cannot be
//  tampered with between sign and verify.
// =========================================================

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
        nonce: payload.nonce,
        sender: payload.sender || null
    };
}

// -----------------------------------------------------
//  POST /api/sign
//  Body: { ticketId, expiryDays?, nonce?, sender? }
//  Returns: { token, ticketId, expiry, nonce, sender }
// -----------------------------------------------------
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

            const sender = body?.sender ?? null;
            if (sender !== null) {
                if (typeof sender !== 'string' || !sender.includes('@') || sender.length > 320) {
                    return { status: 400, jsonBody: { error: 'sender must be a valid email string' } };
                }
            }

            const expiryDays = Number(body?.expiryDays ?? 7);
            const expiry = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString();
            const nonce = body?.nonce || crypto.randomBytes(16).toString('hex');

            const payload = { ticketId: String(ticketId), expiry, nonce };
            if (sender) payload.sender = sender;

            const token = sign(payload);

            return {
                status: 200,
                jsonBody: { token, ticketId: String(ticketId), expiry, nonce, sender: sender || null }
            };
        } catch (err) {
            context.error('sign error', err);
            return { status: 500, jsonBody: { error: 'sign_failed', detail: err.message } };
        }
    }
});

// -----------------------------------------------------
//  POST /api/verify
//  Body: { token }
//  Returns on valid:   { valid: true, ticketId, expiry, nonce, sender }
//  Returns on invalid: { valid: false, reason }
// -----------------------------------------------------
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

// =============================================================================
// ADDITIONS to src/index.js — paste these BELOW the existing 'verify' endpoint
// =============================================================================
//
// Two new endpoints for the customer firm portal:
//   POST /api/signFirm    — issues a token tied to a firm (Client SP item ID)
//   POST /api/verifyFirm  — verifies a firm token (used by Phase 7 webhook)
//
// Token payload shape:
//   { firmId: <string>, expiry, nonce, sender? }
//
// firmId is intentionally a different field than ticketId so a firm token can
// never be replayed against the close/assign/rate flows (which check ticketId).
//
// =============================================================================

// -----------------------------------------------------
//  POST /api/signFirm
//  Body: { clientId | firmId, expiryDays?, nonce?, sender? }
//  Returns: { token, firmId, expiry, nonce, sender }
// -----------------------------------------------------
app.http('signFirm', {
    methods: ['POST'],
    authLevel: 'function',
    handler: async (request, context) => {
        try {
            const body = await request.json();
            // Accept either clientId or firmId on the input for ergonomics
            const firmIdInput = body?.firmId ?? body?.clientId;
            if (!firmIdInput && firmIdInput !== 0) {
                return { status: 400, jsonBody: { error: 'firmId (or clientId) required' } };
            }

            const sender = body?.sender ?? null;
            if (sender !== null) {
                if (typeof sender !== 'string' || !sender.includes('@') || sender.length > 320) {
                    return { status: 400, jsonBody: { error: 'sender must be a valid email string' } };
                }
            }

            const expiryDays = Number(body?.expiryDays ?? 90);
            if (!Number.isFinite(expiryDays) || expiryDays < 1 || expiryDays > 365) {
                return { status: 400, jsonBody: { error: 'expiryDays must be 1..365' } };
            }
            const expiry = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000).toISOString();
            const nonce = body?.nonce || crypto.randomBytes(16).toString('hex');

            const payload = { firmId: String(firmIdInput), expiry, nonce };
            if (sender) payload.sender = sender;

            const token = sign(payload);

            return {
                status: 200,
                jsonBody: { token, firmId: String(firmIdInput), expiry, nonce, sender: sender || null }
            };
        } catch (err) {
            context.error('signFirm error', err);
            return { status: 500, jsonBody: { error: 'sign_failed', detail: err.message } };
        }
    }
});

// -----------------------------------------------------
//  POST /api/verifyFirm
//  Body: { token }
//  Returns valid:   { valid: true, firmId, expiry, nonce, sender }
//  Returns invalid: { valid: false, reason }
// -----------------------------------------------------
function verifyFirmToken(token) {
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
    // Critically: this requires firmId, not ticketId. Reuse of close/assign tokens
    // here would fail because those payloads have ticketId, not firmId.
    if (!payload.firmId || !payload.expiry || !payload.nonce) {
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
        firmId: payload.firmId,
        expiry: payload.expiry,
        nonce: payload.nonce,
        sender: payload.sender || null
    };
}

app.http('verifyFirm', {
    methods: ['POST'],
    authLevel: 'function',
    handler: async (request, context) => {
        try {
            const body = await request.json();
            const token = body?.token;
            if (!token) {
                return { status: 400, jsonBody: { valid: false, reason: 'missing_token' } };
            }
            const result = verifyFirmToken(token);
            return { status: 200, jsonBody: result };
        } catch (err) {
            context.error('verifyFirm error', err);
            return { status: 500, jsonBody: { valid: false, reason: 'verify_error', detail: err.message } };
        }
    }
});
