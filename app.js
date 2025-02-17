require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

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
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

    const { access_token, refresh_token } = response.data;

    // Set tokens in httpOnly cookies
    res.cookie('access_token', access_token, { httpOnly: true, secure: true });
    res.cookie('refresh_token', refresh_token, { httpOnly: true, secure: true });

    res.redirect(process.env.FRONTEND_URL);
  } catch (err) {
    console.error(err);
    res.status(500).send('Token exchange failed');
  }
});

// Example protected route
app.get('/protected', (req, res) => {
  const token = req.cookies.access_token;
  if (!token) {
    return res.status(401).send('Unauthorized');
  }
  res.send('Protected resource accessed!');
});

const port = 4000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
