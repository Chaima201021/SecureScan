(function () {
  "use strict";

  const apiBase = window.SECURESCAN_API_BASE
    || (window.location.protocol === "file:" ? "http://localhost:3000" : (window.location.port === "3000" ? "" : "http://localhost:3000"));

  function getToken() {
    return localStorage.getItem("securescan_token");
  }

  function setToken(token) {
    localStorage.setItem("securescan_token", token);
  }

  function clearToken() {
    localStorage.removeItem("securescan_token");
  }

  function setUserEmail(email) {
    localStorage.setItem("securescan_user_email", email || "");
  }

  function getUserEmail() {
    return localStorage.getItem("securescan_user_email") || "";
  }

  async function fetchMe() {
    const token = getToken();
    if (!token) {
      return null;
    }

    const response = await fetch(`${apiBase}/api/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      clearToken();
      return null;
    }

    const data = await response.json();
    setUserEmail(data.user?.email || "");
    return data.user || null;
  }

  function updateAuthUi() {
    const authButtons = document.getElementById("auth-buttons");
    const userBadge = document.getElementById("user-badge");
    const logoutButton = document.getElementById("logout-button");

    const email = getUserEmail();
    if (getToken() && email) {
      if (authButtons) {
        authButtons.classList.add("d-none");
      }
      if (userBadge) {
        userBadge.textContent = email;
        userBadge.classList.remove("d-none");
      }
      if (logoutButton) {
        logoutButton.classList.remove("d-none");
      }
      return;
    }

    if (authButtons) {
      authButtons.classList.remove("d-none");
    }
    if (userBadge) {
      userBadge.classList.add("d-none");
    }
    if (logoutButton) {
      logoutButton.classList.add("d-none");
    }
  }

  async function ensureAuth() {
    try {
      await fetchMe();
    } catch (error) {
      clearToken();
    } finally {
      updateAuthUi();
    }
  }

  window.securescanAuth = {
    getToken,
    setToken,
    clearToken,
    setUserEmail,
    getUserEmail,
    fetchMe,
    ensureAuth,
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest("#logout-button");
    if (!target) {
      return;
    }

    clearToken();
    setUserEmail("");
    updateAuthUi();
    window.location.href = "index.html";
  });

  ensureAuth();
})();
