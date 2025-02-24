require('dotenv').config();
const cors = require('cors');
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { jwtDecode } = require('jwt-decode')

const TOKEN_TYPE_ACCESS_TOKEN = 'access_token'
const TOKEN_TYPE_REFRESH_TOKEN = 'refresh_token'

const COOKIE_ACCESS_TOKEN = TOKEN_TYPE_ACCESS_TOKEN
const COOKIE_REFRESH_TOKEN = TOKEN_TYPE_REFRESH_TOKEN

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

const app = express();
app.use(cookieParser());

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}))

const KK_GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code'
const KK_GRANT_TYPE_REFRESH_TOKEN = TOKEN_TYPE_REFRESH_TOKEN

const KK_CONFIG = {
  url: `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect`,
  client_id: process.env.KEYCLOAK_CLIENT_ID,
  client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
  redirect_uri: process.env.REDIRECT_URI
};

const KK_ENDPOINT_TOKEN = `${KK_CONFIG.url}/token`;
const KK_ENDPOINT_TOKEN_INTROSPECT = `${KK_ENDPOINT_TOKEN}/introspect`;

async function validateToken(token, tokenTypeHint) {
  try {
    const response = await axios.post(
      KK_ENDPOINT_TOKEN_INTROSPECT,
      new URLSearchParams({
        client_id: KK_CONFIG.client_id,
        client_secret: KK_CONFIG.client_secret,
        token: token,
        token_type_hint: tokenTypeHint,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
      }
    );

    const isValid = response.data.active

    console.log('Validating token:', token);
    console.log('Validation result: ', isValid);
    return isValid;
  } catch (error) {
    console.error('Provided token is NOT valid. Access is prohibited. Token: ', token);
    console.error('Token introspection details: ', error);
  }
  return false;
}

const PROTECTED_ROUTES = ['/api/', '/logout'];

function isProtectedRoute(route) {
  return PROTECTED_ROUTES.some(privateRoutePrefix => route.startsWith(privateRoutePrefix));
}

/**
 * Middleware is supposed to check 2 things:
 * 1. If access token is expired
 * 2. If access token is invalid (not just expired)
 * Middleware is enabled only for PROTECTED API.
 */
app.use(async (req, res, next) => {
  const isProtectedApi = isProtectedRoute(req.path);

  console.log('Path: ', req.path);

  // If public API - skip the middleware
  if (!isProtectedApi) {
    return next();
  }

  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

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
    return res.status(403).send('Provided access token is invalid. Access blocked. See backend logs for more details.')
  }

  // If provided access token is expired
  if (isExpired) {
    try {
      // Refresh the tokens in Keycloak
      const response = await axios.post(
        KK_ENDPOINT_TOKEN,
        new URLSearchParams({
          client_id: KK_CONFIG.client_id,
          client_secret: KK_CONFIG.client_secret,
          grant_type: KK_GRANT_TYPE_REFRESH_TOKEN,
          refresh_token: refreshToken
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
        }
      );

      const { access_token, refresh_token } = response.data

      // Set tokens in httpOnly cookies
      res.cookie(COOKIE_ACCESS_TOKEN, access_token, {
        httpOnly: true,
        // secure: true,
      });
      res.cookie(COOKIE_REFRESH_TOKEN, refresh_token, {
        httpOnly: true,
        // secure: true,
      });
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

// Require access token and refresh token from Keycloak
app.get('/request-token', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).json({ message: 'No authorization code provided' });
  }

  try {
    const response = await axios.post(
      KK_ENDPOINT_TOKEN,
      new URLSearchParams({
        client_id: KK_CONFIG.client_id,
        client_secret: KK_CONFIG.client_secret,
        grant_type: KK_GRANT_TYPE_AUTHORIZATION_CODE,
        code: code,
        redirect_uri: KK_CONFIG.redirect_uri,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { access_token, refresh_token } = response.data;

    // Set tokens in httpOnly cookies
    res.cookie(COOKIE_ACCESS_TOKEN, access_token, {
      httpOnly: true,
      // secure: true,
    });
    res.cookie(COOKIE_REFRESH_TOKEN, refresh_token, {
      httpOnly: true,
      // secure: true,
    });

    const tokenPayload = getTokenPayload(access_token);

    return res.json({
      userInfo: {
        name: tokenPayload.name,
        firstName: tokenPayload.given_name,
        lastName: tokenPayload.family_name,
        email: tokenPayload.email,
        emailVerified: tokenPayload.email_verified,
      }
    })
  } catch (err) {
    console.error(err);
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

// Server running
const port = 4000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
