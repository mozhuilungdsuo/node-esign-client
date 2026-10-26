import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

import 'dotenv/config';
import ejs from 'ejs';
import express from 'express';
import session from 'express-session';
import multer from 'multer';

const requiredConfig = ['IAM_BASE_URL', 'IAM_ESIGN_API_KEY', 'ESIGN_COMPLETION_URL', 'SESSION_SECRET'];

for (const name of requiredConfig) {
  if (!process.env[name]) {
    throw new Error(`${name} must be configured. Copy .env.example to .env first.`);
  }
}

const config = {
  port: Number(process.env.PORT ?? 3000),
  iamBaseUrl: process.env.IAM_BASE_URL.replace(/\/$/, ''),
  iamEsignApiKey: process.env.IAM_ESIGN_API_KEY,
  completionUrl: process.env.ESIGN_COMPLETION_URL,
  sessionSecret: process.env.SESSION_SECRET,
};

const allowedMimeTypes = new Set(['application/pdf', 'image/jpeg', 'image/png']);
// This is deliberately server-side: neither XML artifacts nor UID tokens are
// written into the session cookie or sent back to the browser. Replace these
// in-memory stores with application database records in production.
const artifactsBySession = new Map();
const reusableUidTokensBySession = new Map();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024, files: 1 },
  fileFilter: (_request, file, callback) => {
    callback(null, allowedMimeTypes.has(file.mimetype));
  },
});

const app = express();

app.set('view engine', 'ejs');
app.set('views', fileURLToPath(new URL('./views', import.meta.url)));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'node-esign-example',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
}));

class IamError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function transactions(request) {
  request.session.esignTransactions ??= {};

  return request.session.esignTransactions;
}

function artifacts(request) {
  let sessionArtifacts = artifactsBySession.get(request.sessionID);

  if (!sessionArtifacts) {
    sessionArtifacts = new Map();
    artifactsBySession.set(request.sessionID, sessionArtifacts);
  }

  return sessionArtifacts;
}

function reusableUidToken(request) {
  return reusableUidTokensBySession.get(request.sessionID) ?? null;
}

function storeArtifacts(request, transactionId, payload) {
  artifacts(request).set(transactionId, {
    esignXml: payload.esign_xml ?? null,
    esignResponseXml: payload.esign_response_xml ?? null,
    uidToken: payload.uid_token ?? null,
  });

  if (typeof payload.uid_token === 'string' && payload.uid_token !== '') {
    reusableUidTokensBySession.set(request.sessionID, payload.uid_token);
  }
}

function renderHome(request, response, { error = null, status = 200 } = {}) {
  response.status(status).render('home', {
    error,
    hasReusableUidToken: reusableUidToken(request) !== null,
  });
}

function matchesState(expected, actual) {
  if (typeof expected !== 'string' || typeof actual !== 'string') {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);

  return expectedBuffer.length === actualBuffer.length && timingSafeEqual(expectedBuffer, actualBuffer);
}

function downloadName(filename) {
  const base = filename.replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9._-]/g, '_') || 'document';

  return `${base}-signed.pdf`;
}

async function iamFetch(path, options = {}) {
  const response = await fetch(`${config.iamBaseUrl}${path}`, {
    ...options,
    headers: {
      Accept: 'application/json',
      'X-IAM-eSign-Key': config.iamEsignApiKey,
      ...options.headers,
    },
  });

  if (response.ok) {
    return response;
  }

  const payload = await response.json().catch(() => null);
  throw new IamError(response.status, payload?.message ?? `IAM request failed with HTTP ${response.status}.`);
}

async function transactionStatus(transactionId) {
  const response = await iamFetch(`/api/esign/requests/${encodeURIComponent(transactionId)}`);

  return response.json();
}

async function transactionArtifacts(transactionId) {
  const response = await iamFetch(`/api/esign/requests/${encodeURIComponent(transactionId)}/artifacts`);

  return response.json();
}

app.get('/', (request, response) => {
  renderHome(request, response);
});

app.post('/esign', upload.single('document'), async (request, response, next) => {
  try {
    if (!request.file) {
      renderHome(request, response, { status: 422, error: 'Upload a PDF, JPG, or PNG document up to 20 MB.' });

      return;
    }

    const mode = typeof request.body.mode === 'string' ? request.body.mode : '';

    if (!['direct', 'visible'].includes(mode)) {
      renderHome(request, response, { status: 422, error: 'Select either direct or visible signing mode.' });

      return;
    }

    if (mode === 'direct' && request.file.mimetype !== 'application/pdf') {
      renderHome(request, response, { status: 422, error: 'Direct signing requires a PDF document.' });

      return;
    }

    const signerName = typeof request.body.signer_name === 'string' ? request.body.signer_name.trim() : '';
    const signatureFieldName = typeof request.body.signature_field_name === 'string'
      ? request.body.signature_field_name.trim()
      : '';
    const signaturePosition = typeof request.body.signature_position === 'string'
      ? request.body.signature_position.trim()
      : '';

    if (mode === 'visible' && signerName === '') {
      renderHome(request, response, { status: 422, error: 'Signer name is required for visible signing.' });

      return;
    }

    if (mode === 'visible' && signaturePosition !== ''
      && !['top-left', 'top-right', 'bottom-left', 'bottom-right'].includes(signaturePosition)) {
      renderHome(request, response, { status: 422, error: 'Choose a valid visible signature position.' });

      return;
    }

    if (signerName.length > 120 || signatureFieldName.length > 120) {
      renderHome(request, response, { status: 422, error: 'Signer name and signature field name must be at most 120 characters.' });

      return;
    }

    const state = randomBytes(32).toString('base64url');
    const form = new FormData();
    form.append('document', new Blob([request.file.buffer], { type: request.file.mimetype }), request.file.originalname);
    form.append('client_reference', `node-${randomUUID().replaceAll('-', '')}`);
    form.append('completion_url', config.completionUrl);
    form.append('state', state);
    form.append('mode', mode);

    // The checkbox carries no secret. The token is looked up from server-side
    // storage and supplied only to IAM in this server-to-server request.
    if (request.body.reuse_uid_token === 'on') {
      const uidToken = reusableUidToken(request);

      if (uidToken) {
        form.append('uid_token', uidToken);
      }
    }

    if (mode === 'visible') {
      form.append('signer_name', signerName);

      if (signaturePosition !== '') {
        form.append('signature_position', signaturePosition);
      }
    } else {
      form.append('signature_field_name', signatureFieldName || 'Node application approval');
    }

    const iamResponse = await iamFetch('/api/esign/requests', {
      method: 'POST',
      body: form,
    });
    const transaction = await iamResponse.json();

    transactions(request)[transaction.transaction_id] = {
      state,
      filename: request.file.originalname,
    };

    if (transaction.handoff_url) {
      response.redirect(303, transaction.handoff_url);

      return;
    }

    response.redirect(303, `/esign/complete?esign_transaction_id=${encodeURIComponent(transaction.transaction_id)}&state=${encodeURIComponent(state)}`);
  } catch (error) {
    next(error);
  }
});

app.get('/esign/complete', async (request, response, next) => {
  try {
    const transactionId = typeof request.query.esign_transaction_id === 'string' ? request.query.esign_transaction_id : '';
    const state = typeof request.query.state === 'string' ? request.query.state : '';
    const transaction = transactions(request)[transactionId];

    if (!transaction || !matchesState(transaction.state, state)) {
      response.status(403).render('completion', {
        error: 'This eSign completion does not belong to the current browser session.',
        result: null,
        transactionId: null,
        artifactsStored: false,
      });

      return;
    }

    const result = await transactionStatus(transactionId);
    let artifactsStored = false;

    if (result.status === 'completed') {
      const artifactPayload = await transactionArtifacts(transactionId);
      storeArtifacts(request, transactionId, artifactPayload);
      artifactsStored = true;
    }

    response.render('completion', { error: null, result, transactionId, artifactsStored });
  } catch (error) {
    next(error);
  }
});

app.get('/esign/:transactionId/download', async (request, response, next) => {
  try {
    const transaction = transactions(request)[request.params.transactionId];

    if (!transaction) {
      response.sendStatus(403);

      return;
    }

    const result = await transactionStatus(request.params.transactionId);

    if (result.status !== 'completed') {
      response.status(409).send('The signed document is not ready.');

      return;
    }

    const iamResponse = await iamFetch(`/api/esign/requests/${encodeURIComponent(request.params.transactionId)}/download`);
    response.status(200);
    response.setHeader('Content-Type', iamResponse.headers.get('content-type') ?? 'application/pdf');
    response.setHeader('Content-Disposition', `attachment; filename="${downloadName(transaction.filename)}"`);
    await pipeline(Readable.fromWeb(iamResponse.body), response);
  } catch (error) {
    next(error);
  }
});

app.use((error, request, response, _next) => {
  if (error instanceof multer.MulterError || error instanceof IamError) {
    renderHome(request, response, { status: error instanceof IamError ? error.status : 422, error: error.message });

    return;
  }

  console.error(error);
  renderHome(request, response, {
    status: 500,
    error: 'Unable to complete the eSign request. Check the server log.',
  });
});

app.listen(config.port, () => {
  console.log(`Node eSign example listening on http://localhost:${config.port}`);
});
