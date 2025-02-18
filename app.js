require('dotenv').config();
const cors = require('cors');
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}))

const keycloakConfig = {
  url: `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
  client_id: process.env.KEYCLOAK_CLIENT_ID,
  client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
  redirect_uri: process.env.REDIRECT_URI
};

// Handle Keycloak callback
app.get('/request-token', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('No code provided');
  }

  try {
    const response = await axios.post(keycloakConfig.url, new URLSearchParams({
      client_id: keycloakConfig.client_id,
      client_secret: keycloakConfig.client_secret,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: keycloakConfig.redirect_uri
    }), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const { access_token, refresh_token } = response.data;

    // Set tokens in httpOnly cookies
    res.cookie('access_token', access_token, {
      httpOnly: true,
      // secure: true,
      sameSite: 'lax',
      path: '/',
      domain: 'localhost'
    });
    res.cookie('refresh_token', refresh_token, {
      httpOnly: true,
      // secure: true,
      sameSite: 'lax',
      path: '/',
      domain: 'localhost'
    });

    return res.json({ success: true })
  } catch (err) {
    console.error(err);
    res.status(500).send('Token exchange failed');
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
    authenticated: true,
    message: 'Access token found',
    tokenPreview: accessToken.substring(0, 10) + '...'
  });
});

const port = 4000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
