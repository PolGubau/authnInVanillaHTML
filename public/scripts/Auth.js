import API from "./API.js";
import Router from "./Router.js";

const Auth = {
  isLoggedIn: false,
  account: null,
  postLogin: async (response, user) => {
    if (response.ok) {
      Auth.isLoggedIn = true;
      Auth.account = user;
      Auth.updateStatus();
      Router.go("/account");
    } else {
      alert(response.message);
    }

    // credential management API storage
    if (window.PasswordCredential && user.password) {
      const credentials = new PasswordCredential({
        id: user.email,
        password: user.password,
        name: user.email,
      });

      try {
        navigator.credentials.store(credentials);
      } catch (error) {
        console.log("Error storing credentials: " + error);
      }
    }
  },

  loginFromGoogle: async (data) => {
    const response = await API.loginFromGoogle({ credential: data });
    Auth.postLogin(response, {
      name: response.name,
      email: response.email,
    });
  },
  checkAuthOptions: async () => {
    const response = await API.checkAuthOptions({
      email: document.getElementById("login_email").value,
    });
    Auth.loginStep = 2;
    if (response.password) {
      document.getElementById("login_section_password").hidden = false;
    }
    if (response.webauthn) {
      document.getElementById("login_section_webauth").hidden = false;
    }
  },

  register: async (event) => {
    event.preventDefault();
    const user = {
      name: document.getElementById("register_name").value,
      email: document.getElementById("register_email").value,
      password: document.getElementById("register_password").value,
    };
    const response = await API.register(user);
    Auth.postLogin(response, user);
  },
  addWebAuthn: async (event) => {
    if (event) event.preventDefault();
    const options = await API.webAuthn.registrationOptions();
    options.authenticatorSelection.residentKey = "required";
    options.authenticatorSelection.requireResidentKey = true;
    options.extensions = {
      credProps: true,
    };

    const authRes = await SimpleWebAuthnBrowser.startRegistration(options);

    const verificationRes = await API.webAuthn.registrationVerification(
      authRes
    );

    if (verificationRes.ok) {
      alert("WebAuthn registered!");
    } else {
      alert(verificationRes.message);
    }
  },

  webAuthLogin: async (event) => {
    if (event) event.preventDefault();
    const email = document.getElementById("login_email").value;
    if (!email) return alert("Please enter your email first");
    const options = await API.webAuthn.loginOptions(email);
    const loginRes = await SimpleWebAuthnBrowser.startAuthentication(options);
    const verificationRes = await API.webAuthn.loginVerification(
      email,
      loginRes
    );
    if (verificationRes.ok) {
      Auth.postLogin(verificationRes, verificationRes.user);
    } else {
      alert(verificationRes.message);
    }
  },

  login: async (event) => {
    if (event) event.preventDefault();

    if (Auth.loginStep == 1) {
      Auth.checkAuthOptions();
    } else {
      // Step 2
      const user = {
        email: document.getElementById("login_email").value,
        password: document.getElementById("login_password").value,
      };
      const response = await API.login(user);
      Auth.postLogin(response, user);
    }
  },

  logout: async () => {
    Auth.isLoggedIn = false;
    Auth.account = null;
    Auth.updateStatus();
    Router.go("/");

    if (window.PasswordCredential) {
      navigator.credentials.preventSilentAccess();
    }
  },

  autoLogin: async () => {
    if (window.PasswordCredential) {
      const credentials = await navigator.credentials.get({ password: true });
      if (!credentials) return;
      document.getElementById("login_email").value = credentials.id;
      document.getElementById("login_password").value = credentials.password;

      if (credentials) {
        const user = {
          email: credentials.id,
          password: credentials.password,
        };
        const response = await API.login(user);
        Auth.postLogin(response, user);
      }
    }
  },

  updateStatus() {
    if (Auth.isLoggedIn && Auth.account) {
      document
        .querySelectorAll(".logged_out")
        .forEach((e) => (e.style.display = "none"));
      document
        .querySelectorAll(".logged_in")
        .forEach((e) => (e.style.display = "block"));
      document
        .querySelectorAll(".account_name")
        .forEach((e) => (e.innerHTML = Auth.account.name));
      document
        .querySelectorAll(".account_username")
        .forEach((e) => (e.innerHTML = Auth.account.email));
    } else {
      document
        .querySelectorAll(".logged_out")
        .forEach((e) => (e.style.display = "block"));
      document
        .querySelectorAll(".logged_in")
        .forEach((e) => (e.style.display = "none"));
    }
  },
  loginStep: 1,
  init: () => {
    document.getElementById("login_section_password").hidden = true;
    document.getElementById("login_section_webauth").hidden = true;
  },
};
Auth.updateStatus();
Auth.autoLogin();

export default Auth;

// make it a global object
window.Auth = Auth;
