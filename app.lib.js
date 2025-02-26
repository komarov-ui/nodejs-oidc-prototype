// This is a copy of app.js with using lib "openid-client" instead of hardcoded requests
import 'dotenv/config';
import express from 'express';
import * as client from "openid-client";
import fs from 'fs';
import https from 'https';

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

// Configuring API

const app = express();
// <TBA>

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

