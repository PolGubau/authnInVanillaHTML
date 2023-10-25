import API from "./API.js";
import Router from "./Router.js";

const Auth = {
  isLoggedIn: false,
  account: null,
  register: async (event) => {
    event.preventDefault();
    const user = {
      username: document.getElementById("register_name").value,
      password: document.getElementById("register_password").value,
      email: document.getElementById("register_email").value,
    };
    const response = await API.register(user);
    console.log(response);
  },
  login: async (event) => {
    event.preventDefault();
    const user = {
      email: document.getElementById("login_email").value,
      password: document.getElementById("login_password").value,
    };
    const response = await API.login(user);
    console.log(response);
    // if (response.ok) {
    //   Auth.isLoggedIn = true;
    //   Auth.account = response;
    //   Auth.updateStatus();
    //   Router.navigate("/dashboard");
    // }
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
  init: () => {},
};
Auth.updateStatus();

export default Auth;

// make it a global object
window.Auth = Auth;
