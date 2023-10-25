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

db.data ||= { users: [] };

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
  const results = db.data.users.filter((user) => user.email === email);
  return results.length > 0 ? results[0] : undefined;
}

// ADD HERE THE REST OF THE ENDPOINTS

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
  const isPasswordCorrect = bcrypt.compareSync(password, userFound.password);

  if (!isPasswordCorrect) {
    res.status(400).send({ ok: false, message: "Credentials are wrong" });
    return;
  }

  res.send({ ok: true, name: userFound.username, email: userFound.email });
});

app.post("/auth/register", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
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
    username,
    password: hashedPassword,
    email,
  };
  db.data.users.push(newUser);
  await db.write();
});

app.get("*", (req, res) => {
  res.sendFile(__dirname + "public/index.html");
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
