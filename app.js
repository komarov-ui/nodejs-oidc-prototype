require('dotenv').config();
const cors = require('cors');
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const { jwtDecode } = require('jwt-decode')

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

const keycloakConfig = {
  url: `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
  client_id: process.env.KEYCLOAK_CLIENT_ID,
  client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
  redirect_uri: process.env.REDIRECT_URI
};

async function validateToken(token, tokenTypeHint) {
  try {
    const response = await axios.post(
      `${keycloakConfig.url}/introspect`,
      new URLSearchParams({
        client_id: keycloakConfig.client_id,
        client_secret: keycloakConfig.client_secret,
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

const PROTECTED_ROUTES = ['/api/']

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
  
  if (!isProtectedApi) {
    return next();
  }

  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  if (!accessToken) {
    return next();
  }

  const tokenPayload = getTokenPayload(accessToken);
  const isExpired = tokenPayload.exp < Math.floor(Date.now() / 1000);

  console.log('Is token expired: ', isExpired)

  const isValid = await validateToken(accessToken, 'access_token');

  console.log('Is token valid: ', isValid)

  if (!isExpired && !isValid) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(403).send('Provided access token is invalid. Access blocked. See backend logs for more details.')
  }

  if (isExpired) {
    try {
      // Revoke the tokens in Keycloak
      const response = await axios.post(
        keycloakConfig.url,
        new URLSearchParams({
          client_id: keycloakConfig.client_id,
          client_secret: keycloakConfig.client_secret,
          grant_type: 'refresh_token',
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
      res.cookie('access_token', access_token, {
        httpOnly: true,
        // secure: true,
      });
      res.cookie('refresh_token', refresh_token, {
        httpOnly: true,
        // secure: true,
      });
    } catch (error) {
      console.error('Error revoking tokens:', error);

      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(401).json({
        message: 'Session is expired.',
      });
    }
  }

  next();
});

// Handle Keycloak callback
app.get('/request-token', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).json({ message: 'No authorization code provided' });
  }

  try {
    const response = await axios.post(
      keycloakConfig.url,
      new URLSearchParams({
        client_id: keycloakConfig.client_id,
        client_secret: keycloakConfig.client_secret,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: keycloakConfig.redirect_uri,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { access_token, refresh_token } = response.data;

    // Set tokens in httpOnly cookies
    res.cookie('access_token', access_token, {
      httpOnly: true,
      // secure: true,
    });
    res.cookie('refresh_token', refresh_token, {
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

app.get('/api/protected-resource', (req, res) => {
  const accessToken = req.cookies.access_token;
  console.log('Received cookies:', req.cookies);

  if (!accessToken) {
    return res.status(401).json({
      authenticated: false,
      message: 'No access token found',
      availableCookies: Object.keys(req.cookies)
    });
  }

  return res.json({
    protectedData: 'This is protected data. You see it because you are authorized.'
  });
});

const port = 4000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
