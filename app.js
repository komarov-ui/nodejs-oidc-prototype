// This is a copy of app.js with using lib "openid-client" instead of hardcoded requests
import 'dotenv/config';
import express from 'express';
import * as client from "openid-client";
import fs from 'fs';
import https from 'https';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { jwtDecode } from 'jwt-decode';

const DEFAULT_TOKEN_PAYLOAD = {
  id: 'sysadm',
  exp: new Date(),
  extensions: {
    gitIntegration: false,
  },
  groups: [],
  name: 'sysadm',
}

function getTokenPayload(token) {
  let tokenPayload
  try {
    tokenPayload = jwtDecode(token)
  } catch (e) {
    console.error(e)
  }
  return tokenPayload ?? DEFAULT_TOKEN_PAYLOAD
}

const TOKEN_TYPE_ACCESS_TOKEN = 'access_token'
const TOKEN_TYPE_REFRESH_TOKEN = 'refresh_token'

const COOKIE_ACCESS_TOKEN = TOKEN_TYPE_ACCESS_TOKEN
const COOKIE_REFRESH_TOKEN = TOKEN_TYPE_REFRESH_TOKEN
const COOKIE_CODE_VERIFIER = 'code_verifier'
const COOKIE_CODE_CHALLENGE = 'code_challenge'
const COOKIE_NONCE = 'nonce'

const AUTH_SERVER_URL = `${process.env.KEYCLOAK_HTTPS_URL}/realms/${process.env.KEYCLOAK_HTTPS_REALM}`

async function discoverAuthServerConfig() {
  console.log()
  console.log('Discovering...', AUTH_SERVER_URL)
  const keycloakConfig = await client.discovery(
    new URL(AUTH_SERVER_URL),
    process.env.KEYCLOAK_HTTPS_CLIENT_ID,
    process.env.KEYCLOAK_HTTPS_CLIENT_SECRET
  );
  console.log('Server Metadata: ', keycloakConfig.serverMetadata())
  console.log()
  return keycloakConfig;
}

const authServerConfiguration = await discoverAuthServerConfig();

const codeChallengeMethod = 'S256';

async function validateToken(token, tokenTypeHint) {
  try {
    const { active: isValid } = await client.tokenIntrospection(
      authServerConfiguration,
      token,
      {
        token_type_hint: tokenTypeHint,
      }
    );

    console.log('Validating token:', token);
    console.log('Validation result: ', isValid);
    return isValid;
  } catch (error) {
    console.error('Provided token is NOT valid. Access is prohibited. Token: ', token);
    console.error('Token introspection details: ', error);
  }
  return false;
}

// Configuring API

const app = express();

// Primary configuration
app.use(cookieParser());
app.use(cors({
  origin: process.env.FRONTEND_HTTPS_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

/**
 * Middleware is supposed to check 2 things:
 * 1. If access token is expired
 * 2. If access token is invalid (not just expired)
 * Middleware is enabled only for PROTECTED API.
 */
const PROTECTED_ROUTES = ['/api/'];

function isProtectedRoute(route) {
  return PROTECTED_ROUTES.some(privateRoutePrefix => route.startsWith(privateRoutePrefix));
}

app.use(async (req, res, next) => {
  const isProtectedApi = isProtectedRoute(req.path);

  console.log('Path: ', req.path);

  // If public API - skip the middleware
  if (!isProtectedApi) {
    return next();
  }

  const accessToken = req.cookies[COOKIE_ACCESS_TOKEN];
  const refreshToken = req.cookies[COOKIE_REFRESH_TOKEN];

  // if there is no provided access token, return HTTP 401 (Unauthorized)
  if (!accessToken) {
    console.log('Received cookies:', req.cookies);
    return res.status(401).send('No provided access token.');
  }

  const tokenPayload = getTokenPayload(accessToken);
  const isExpired = tokenPayload.exp < Math.floor(Date.now() / 1000);

  console.log('Is token expired: ', isExpired)

  const isValid = await validateToken(accessToken, TOKEN_TYPE_ACCESS_TOKEN);

  console.log('Is token valid: ', isValid)

  // If provided access token is invalid and not expired
  if (!isExpired && !isValid) {
    res.clearCookie(COOKIE_ACCESS_TOKEN);
    res.clearCookie(COOKIE_REFRESH_TOKEN);
    return res.status(401).send('Provided access token is invalid. Access blocked. See backend logs for more details.')
  }

  // If provided access token is expired
  if (isExpired) {
    try {
      // Refresh the tokens in Keycloak
      const token = await client.refreshTokenGrant(authServerConfiguration, refreshToken);

      const { access_token, refresh_token } = token;

      // Set tokens in httpOnly cookies
      res.cookie(COOKIE_ACCESS_TOKEN, access_token, { httpOnly: true, secure: true });
      res.cookie(COOKIE_REFRESH_TOKEN, refresh_token, { httpOnly: true, secure: true });
    } catch (error) {
      console.error('Error revoking tokens:', error);

      res.clearCookie(COOKIE_ACCESS_TOKEN);
      res.clearCookie(COOKIE_REFRESH_TOKEN);
      return res.status(401).json({
        message: 'Session is expired.',
      });
    }
  }

  next();
});

app.get('/auth', async (req, res) => {
  const cachedCodeVerifier = req.cookies[COOKIE_CODE_VERIFIER]
  const cachedCodeChallenge = req.cookies[COOKIE_CODE_CHALLENGE]

  const codeVerifier = cachedCodeVerifier ?? client.randomPKCECodeVerifier();
  const codeChallenge = cachedCodeChallenge ?? await client.calculatePKCECodeChallenge(codeVerifier);

  if (!cachedCodeVerifier && !cachedCodeChallenge) {
    res.cookie(COOKIE_CODE_VERIFIER, codeVerifier, { httpOnly: true, secure: true });
    res.cookie(COOKIE_CODE_CHALLENGE, codeChallenge, { httpOnly: true, secure: true });
  }

  // redirect user to as.authorization_endpoint
  const parameters = {
    redirect_uri: process.env.REDIRECT_HTTPS_URI,
    scope: 'openid email',
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
  }

  let nonce

  /**
   * We cannot be sure the AS supports PKCE so we're going to use nonce too. Use
   * of PKCE is backwards compatible even if the AS doesn't support it which is
   * why we're using it regardless.
   */
  if (!authServerConfiguration.serverMetadata().supportsPKCE()) {
    console.log('PKCE not supported, using nonce');
    const cachedNonce = req.cookies[COOKIE_NONCE]
    nonce = cachedNonce ?? client.randomNonce()
    if (!cachedNonce) {
      res.cookie(COOKIE_NONCE, nonce, { httpOnly: true, secure: true });
    }
    parameters.nonce = nonce
  }

  let redirectTo = client.buildAuthorizationUrl(authServerConfiguration, parameters)
  console.log('Authorization URL:', redirectTo.href)

  return res.json({ redirectTo: redirectTo.href })
});

app.get('/auth/token', async (req, res) => {
  try {
    const codeVerifier = req.cookies[COOKIE_CODE_VERIFIER];
    const nonce = req.cookies[COOKIE_NONCE];

    const currentUrl = decodeURIComponent(req.query.currentUrl);
    const token = await client.authorizationCodeGrant(
      authServerConfiguration,
      new URL(currentUrl),
      {
        pkceCodeVerifier: codeVerifier,
        expectedNonce: nonce,
        idTokenExpected: true,
      }
    );

    console.log('Token:', token)

    const { id_token, access_token, refresh_token } = token;

    // Set tokens in httpOnly cookies
    res.cookie(COOKIE_ACCESS_TOKEN, access_token, { httpOnly: true, secure: true });
    res.cookie(COOKIE_REFRESH_TOKEN, refresh_token, { httpOnly: true, secure: true });

    res.clearCookie(COOKIE_CODE_VERIFIER);
    res.clearCookie(COOKIE_CODE_CHALLENGE);
    res.clearCookie(COOKIE_NONCE);

    return res.json({
      idToken: id_token,
      userInfo: getTokenPayload(id_token),
    });
  } catch (err) {
    console.error('Token exchange failed', err);
    res.status(500).json({ message: 'Token exchange failed' });
  }
});

// Examples of protected API
app.get('/api/protected-resource', (req, res) => {
  return res.json({
    protectedData: 'This is protected data. You see it because you are authorized.'
  });
});

app.get('/api/another-protected-resource', (req, res) => {
  return res.json({
    protectedData: 'This is ANOTHER protected data. You see it because you are authorized.'
  });
});

// Running server

const port = 4000;
const privateKey = fs.readFileSync('./ssl/server.key');
const certificate = fs.readFileSync('./ssl/server.crt');

https
  .createServer({
    key: privateKey,
    cert: certificate
  }, app)
  .listen(port, () => console.log(`Server running on https://localhost:${port}`));

