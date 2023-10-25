import express from "express";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import * as url from "url";
import bcrypt from "bcryptjs";
import * as jwtJsDecode from "jwt-js-decode";
import base64url from "base64url";
import SimpleWebAuthnServer from "@simplewebauthn/server";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const app = express();
app.use(express.json());

const adapter = new JSONFile(__dirname + "/auth.json"); // database file
const db = new Low(adapter);
await db.read();

db.data ??= { users: [] };

const rpID = "localhost";
const protocol = "http";
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static("public"));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

function findUser(email) {
  const results = db.data.users?.filter((user) => user.email === email) ?? [];
  return results?.length > 0 ? results[0] : undefined;
}

// ADD HERE THE REST OF THE ENDPOINTS

app.post("/auth/auth-options", async (req, res) => {
  const { email } = req.body;
  const foundUser = findUser(email);

  if (foundUser) {
    res.send({
      password: foundUser.password != false,
      google: foundUser.federated?.google != false,
      webauth: foundUser.webauth,
    });
  } else {
    res.send({
      password: true, // so hackers can't filter responses by pswd failed attempts
    });
  }
});

app.post("/auth/login-google", async (req, res) => {
  let { payload } = jwtJsDecode.jwtDecode(req.body.credential.credential);

  let user = {
    email: payload.email,
    name: payload.given_name + " " + payload.family_name,
    password: null,
  };

  const userFound = findUser(user.email);

  if (userFound) {
    user.federated = { google: payload.aud };

    db.data.users.push(user);
    await db.write();

    res.send({ ok: true, name: user.name, email: user.email });
  } else {
    db.data.users.push({
      ...user,
      federated: { google: payload.aud },
    });

    await db.write();

    res.send({ ok: true, name: user.name, email: user.email });
  }
});

app.post("/auth/login", async (req, res) => {
  // on body we'll have email and password
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).send({ ok: false, message: "Missing fields" });
    return;
  }
  if (password.length < 8) {
    res.status(400).send({
      ok: false,
      message: "Password must be at least 8 characters long",
    });
    return;
  }
  const userFound = findUser(email);
  if (!userFound) {
    res.status(400).send({ ok: false, message: "User not found" });
    return;
  }
  const isPasswordCorrect = bcrypt.compareSync(
    password ?? "",
    userFound.password ?? ""
  );

  if (!isPasswordCorrect) {
    res.status(400).send({ ok: false, message: "Credentials are wrong" });
    return;
  }

  res.send({ ok: true, name: userFound.name, email: userFound.email });
});

app.post("/auth/register", async (req, res) => {
  const { name, password, email } = req.body;

  if (!name || !password || !email) {
    res.status(400).send({ ok: false, message: "Missing fields" });
    return;
  }

  if (password.length < 8) {
    res.status(400).send({
      ok: false,
      message: "Password must be at least 8 characters long",
    });
    return;
  }

  const userFound = findUser(email);
  if (userFound) {
    res.status(400).send({ ok: false, message: "Email already exists" });
    return;
  }

  // user is new
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  const newUser = {
    name,
    password: hashedPassword,
    email,
  };
  db.data.users.push(newUser);
  await db.write();

  res.send({ ok: true, name: name, email });
});

// WebAuth
app.post("/auth/webauth-registration-options", (req, res) => {
  const user = findUser(req.body.email);

  const options = {
    rpName: "Pol Gubau Amores",
    rpID,
    userID: user.email,
    userName: user.name,
    timeout: 60000,
    attestationType: "none",

    /**
     * Passing in a user's list of already-registered authenticator IDs here prevents users from
     * registering the same device multiple times. The authenticator will simply throw an error in
     * the browser if it's asked to perform registration when one of these ID's already resides
     * on it.
     */
    excludeCredentials: user.devices
      ? user.devices.map((dev) => ({
          id: dev.credentialID,
          type: "public-key",
          transports: dev.transports,
        }))
      : [],

    authenticatorSelection: {
      userVerification: "required",
      residentKey: "required",
    },
    /**
     * The two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  const regOptions = SimpleWebAuthnServer.generateRegistrationOptions(options);
  user.currentChallenge = regOptions.challenge;
  db.write();

  res.send(regOptions);
});

app.post("/auth/webauth-registration-verification", async (req, res) => {
  const user = findUser(req.body.user.email);
  const data = req.body.data;

  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    const options = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyRegistrationResponse(
      options
    );
  } catch (error) {
    console.log(error);
    return res.status(400).send({ error: error.toString() });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const existingDevice = user.devices
      ? user.devices.find((device) =>
          new Buffer(device.credentialID.data).equals(credentialID)
        )
      : false;

    if (!existingDevice) {
      const newDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: data.response.transports,
      };
      if (user.devices == undefined) {
        user.devices = [];
      }
      user.webauthn = true;
      user.devices.push(newDevice);
      db.write();
    }
  }

  res.send({ ok: true });
});
app.post("/auth/webauth-login-options", (req, res) => {
  const user = findUser(req.body.email);

  if (!user) {
    res.status(400).send({ ok: false, message: "User not found" });
    return;
  }
  const options = {
    timeout: 60000,
    allowCredentials: [],
    devices:
      user && user.devices
        ? user.devices.map((dev) => ({
            id: dev.credentialID,
            type: "public-key",
            transports: dev.transports,
          }))
        : [],
    userVerification: "required",
    rpID,
  };
  const loginOpts = SimpleWebAuthnServer.generateAuthenticationOptions(options);
  if (user) user.currentChallenge = loginOpts.challenge;
  res.send(loginOpts);
});

app.post("/auth/webauth-login-verification", async (req, res) => {
  const data = req.body.data;
  const user = findUser(req.body.email);
  if (user == null) {
    res.sendStatus(400).send({ ok: false });
    return;
  }

  const expectedChallenge = user.currentChallenge;

  let dbAuthenticator;
  const bodyCredIDBuffer = base64url.toBuffer(data.rawId);

  for (const dev of user.devices) {
    const currentCredential = Buffer(dev.credentialID.data);
    if (bodyCredIDBuffer.equals(currentCredential)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    return res.status(400).send({
      ok: false,
      message: "Authenticator is not registered with this site",
    });
  }

  let verification;
  try {
    const options = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        ...dbAuthenticator,
        credentialPublicKey: new Buffer(
          dbAuthenticator.credentialPublicKey.data
        ), // Re-convert to Buffer from JSON
      },
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyAuthenticationResponse(
      options
    );
  } catch (error) {
    return res.status(400).send({ ok: false, message: error.toString() });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  res.send({
    ok: true,
    user: {
      name: user.name,
      email: user.email,
    },
  });
});
app.get("*", (req, res) => {
  res.sendFile(__dirname + "public/index.html");
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
