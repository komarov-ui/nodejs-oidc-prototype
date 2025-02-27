## oidc-prototype (backend service)

### Running Keycloak Server

Before running frontend and backend service, you must raise up *Keycloak Server*.

It's really simple to do by following Docker command:

```
docker run 
  -p 8443:8443 \
  -p 9000:9000 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=change_me \
  -e KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/conf/server.crt \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/conf/server.key \
  -v C:/<path_to_backend_project>/ssl/server.crt:/opt/keycloak/conf/server.crt \
  -v C:/<path_to_backend_project>/ssl/server.key:/opt/keycloak/conf/server.key \
  quay.io/keycloak/keycloak:26.1.2 \
  start \
  --hostname=localhost
```

It will run your Keycloak Server on address: `https://localhost:8443`
Path to Admin Console: `https://localhost:8443/admin/master/console/`
Credentials for Admin Console:

- Username: `admin`
- Password: `change_me`

This instance of Keycloak Server is run in production mode with enabled HTTPS.

After first starting up Keycloak Server you will be able to configure it Admin Console and save changes by commiting changed container as image by command:

```
docker commit <CONTAINER_ID> <IMAGE_NAME>:<IMAGE_TAG>
```

You can use this image instead of `quay.io/keycloak/keycloak:26.1.2` and use flag `--optimized`.

### Adjusting Keycloak Server

Go to Admin Console ( `https://localhost:8443/admin/master/console/`).

#### Create realm

1. Sign In with provided default credentials.

2. Click on realms dropdown at the top-left corner.

3. Click on "Create realm".

4. Put "oidc-app" in "Realm name" and click "Create".

#### Create user

1. Select "oidc-app" in realms dropdown.

2. Go to "Users" tab in menu.

3. Click on "Add user".

4. Put any username, email, first name, last name.

5. Click no "Create".

6. After navigation to user page, go to "Credentials" tab.

7. Click on "Set password".

8. Disable "Temporary" flag, set password and repeat password. Click "Save".

#### Create client

1. Select "oidc-app" in realms dropdown.

2. Go to "Clients" tab in menu.

3. Click on "Create client".

4. Client ID: "test-oidc-client".

5. Click on "Next".

6. Enable "Client authentication".

7. Authentication flow: must be only enabled "Standard flow".

8. Valid Redirect URLs:

```
https://localhost:5173/*
```

9. Valid post logout redirect URIs:

```
https://localhost:5173/*
```

9. Web Origins:

```
https://localhost:5173
```

10. Click on "Save".

11. After navigating to client page, go to tab "Credentials".

12. Copy "Client secret" and put it into .env file in backend service in appropriate variable (KEYCLOAK_HTTPS_CLIENT_SECRET).

#### Create GitHub OAuth2 app for example of identity broker mode

1. Go to your GitHub account.

2. Go to "Settings" -> "Developer Settings" -> "OAuth2 Apps".

3. Click on "New OAuth2 App".

4. Set any available application name (is not used in the prototype).

5. Set "Homepage URL" as `https://localhost:5173`.

6. Set "Authorization callback URL" as `https://localhost:5173/login`.

7. Click on "Register application".

8. After navigation to app page, save "Client ID" and "Client secret" values.

9. Go to Keycloak Admin Console.

10. Select "oidc-app" in realms dropdown.

11. Go to "Identity providers" tab.

12. Click on "GitHub provider".

13. Set "Client ID" and "Client secret" into values saved from GitHub app page.

14. Click on "Add".

#### Set session and token lifespan

1. Select "oidc-app" in realms dropdown.

2. Go to "Realms settings".

3. Go to tab "Sessions".

4. Set "SSO Session Idle" into 2 minutes.

It may be your time, just remember it and pay attention that session idle time must be more than access token lifespan.

5. Go to tab "Tokens".

5. Set "Access Token Lifespan" into 1 minute.

It may be your time, just remember it and pay attention that access token lifespan must be less than session idle time.

*Test case*

0) Go to "Protcted Page".

1) Login in prototype from Frontend side.

2) Copy access token from cookies into some text file.

3) Wait for <Access Token Lifespan>.

4) Refresh page "Protected Page".

5) Copy access token from cookies AGAIN into some text file.

6) Compare it with previous token: they must be different.

7) Wait for <SSO Session Idle>.

8) Refresh page "Protected Page". You must be redirected into Keycloak Login Page.

### Getting Started

#### 1. Install packages

```
npm ci
```

#### 2. Generate self-signed certificates

*ATTENTION*: If you already have certificate and key, you may go to step 3.

<TBA>

#### 3. Create folder "ssl" in root of the project

#### 4. Put generated certificate and key into the folder "ssl"

#### 5. Run backend

```
node app.js
```