// ===========================
//  Reveal a password entry
// ===========================
function revealPassword(event, id) {
  event.preventDefault();
  const span = document.getElementById('pw-' + id);
  const button = event.target;

  fetch(`/decrypt/${id}`)
    .then(res => {
      if (res.status === 401) {
        window.location.href = "/unlock";
        return;
      }
      return res.json();
    })
    .then(data => {
      if (!data) return;
      if (data.password) {
        span.textContent = data.password;
        button.disabled = true;
        setTimeout(() => {
          span.textContent = "••••••";
          button.disabled = false;
        }, 5000);
      } else {
        span.textContent = "Error";
      }
    });
}

// ===========================
//  Search filter (Vault list)
// ===========================
function filterPasswords() {
  const input = document.getElementById("searchInput");
  const filter = input.value.toLowerCase();
  const entries = document.querySelectorAll(".vault-list li");

  entries.forEach(entry => {
    const text = entry.textContent.toLowerCase();
    entry.style.display = text.includes(filter) ? "" : "none";
  });
}

// ===========================
//  Check HIBP (pwned passwords)
// ===========================
async function checkPwned(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await response.text();

  return text.includes(suffix);
}

// ===========================
//  Password strength meter
// ===========================
function handlePasswordStrength() {
  const passwordInput = document.getElementById("password");
  const strengthText = document.getElementById("strength-text");
  const strengthBar = document.getElementById("strength-bar");
  let breachWarning = document.getElementById("breach-warning");

  if (!passwordInput || !strengthText || !strengthBar) return;

  if (!breachWarning) {
    breachWarning = document.createElement("div");
    breachWarning.id = "breach-warning";
    breachWarning.style.color = "red";
    breachWarning.style.marginTop = "5px";
    passwordInput.parentNode.appendChild(breachWarning);
  }

  passwordInput.addEventListener("input", async () => {
    const val = passwordInput.value.trim();
    let score = 0;

    if (val.length >= 8) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    let strength = "—";
    let color = "gray";
    let width = "0%";

    if (val.length === 0) {
      strength = "—";
      color = "gray";
      width = "0%";
    } else {
      switch (score) {
        case 0:
        case 1:
          strength = "Weak";
          color = "red";
          width = "25%";
          break;
        case 2:
          strength = "Moderate";
          color = "orange";
          width = "50%";
          break;
        case 3:
          strength = "Good";
          color = "goldenrod";
          width = "75%";
          break;
        case 4:
          strength = "Strong";
          color = "green";
          width = "100%";
          break;
      }
    }

    strengthText.textContent = `Strength: ${strength}`;
    strengthBar.style.backgroundColor = color;
    strengthBar.style.width = width;

    if (val.length >= 8) {
      const pwned = await checkPwned(val);
      breachWarning.textContent = pwned
        ? "⚠️ This password has been found in a data breach. Please choose a different one."
        : "";
    } else {
      breachWarning.textContent = "";
    }
  });

  if (passwordInput.value.length > 0) {
    passwordInput.dispatchEvent(new Event("input"));
  }
}



// ===========================
// Generate a Secure Password
// ===========================
function generatePassword() {
  const length = 16; // Default password length
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[]|:;<>,.?/~`-=";
  let password = "";

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset.charAt(randomIndex);
  }

  const passwordInput = document.getElementById("password");
  const generatedInput = document.getElementById("generated-password");

  if (passwordInput && generatedInput) {
    passwordInput.value = password;
    generatedInput.value = password;

    // Immediately trigger strength meter update
    if (typeof Event === 'function') {
      passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
    } else { 
      // Fallback for older browsers
      const event = document.createEvent('Event');
      event.initEvent('input', true, true);
      passwordInput.dispatchEvent(event);
    }
  }
}


function copyGeneratedPassword() {
  const generatedInput = document.getElementById("generated-password");
  const copyBtn = event.target;

  if (generatedInput && generatedInput.value.trim() !== "") {
    navigator.clipboard.writeText(generatedInput.value)
      .then(() => {
        flashMessage("Password copied to clipboard!", "success");
        copyBtn.disabled = true;
        const originalText = copyBtn.textContent;
        copyBtn.textContent = "Copied";
        
        setTimeout(() => {
          copyBtn.textContent = originalText;
          copyBtn.disabled = false;
        }, 1500);
      });
  } else {
    flashMessage("No password to copy. Generate one first!", "error");
  }
}



function checkPasswordStrengthDirect(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 1) {
    return "Weak";
  } else if (score === 2) {
    return "Moderate";
  } else if (score === 3) {
    return "Good";
  } else {
    return "Strong";
  }
}

// ===========================
// Dark mode toggle (vault only)
// ===========================
function handleThemeToggle() {
  const body = document.body;
  const toggle = document.getElementById("theme-toggle");
  const currentPath = window.location.pathname;
  const darkPages = ["/vault", "/settings", "/passwords", "/edit", "/add"];
  
  const savedTheme = localStorage.getItem("theme") || "light";  // Default to light if no value saved

  const isVaultPage = darkPages.some(p => currentPath.startsWith(p));

  if (isVaultPage) {
    // Inside Vault area
    if (savedTheme === "dark") {
      body.classList.add("dark-mode");
    } else {
      body.classList.remove("dark-mode");
    }

    if (toggle) {
      toggle.checked = savedTheme === "dark";

      toggle.addEventListener("change", () => {
        if (toggle.checked) {
          body.classList.add("dark-mode");
          localStorage.setItem("theme", "dark");
        } else {
          body.classList.remove("dark-mode");
          localStorage.setItem("theme", "light");
        }
      });
    }

  } else {
    // Outside vault (login, signup, home)
    body.classList.remove("dark-mode");
    localStorage.setItem("theme", "light"); // Force light outside vault
  }
}






// ===========================
// Sidebar toggle (mobile)
// ===========================
function handleSidebarToggle() {
  const toggleBtn = document.getElementById("toggleSidebar");
  const sidebar = document.querySelector(".sidebar");

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }
}

// ===========================
// Session timeout warning
// ===========================
function handleInactivityLock() {
  const modal = document.getElementById("sessionModal");
  const sessionMsg = document.getElementById("sessionMessage");
  const stayBtn = document.getElementById("stayButton");

  const currentPath = window.location.pathname;
  const vaultPages = ["/vault", "/settings", "/passwords", "/edit"];
  const isVaultPage = vaultPages.some(p => currentPath.startsWith(p));

  if (!isVaultPage) return;

  const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
  let warningTimer, redirectTimer, countdownTimer;
  let isModalActive = false;

  function resetTimers(force = false) {
    if (isModalActive && !force) return;

    clearTimeout(warningTimer);
    clearTimeout(redirectTimer);
    clearInterval(countdownTimer);
    if (modal) modal.style.display = "none";
    isModalActive = false;

    warningTimer = setTimeout(() => {
      if (modal && sessionMsg) {
        let remaining = 30;
        sessionMsg.innerHTML = `You'll be locked out in <span id="countdown">30</span> seconds due to inactivity.`;
        modal.style.display = "flex";
        isModalActive = true;

        countdownTimer = setInterval(() => {
          remaining--;
          const el = document.getElementById("countdown");
          if (el) el.textContent = remaining;
          if (remaining <= 0) clearInterval(countdownTimer);
        }, 1000);
      }
    }, SESSION_TIMEOUT_MS - 30000);

    redirectTimer = setTimeout(() => {
      console.log("⏰ Session expired. Redirecting to /unlock");
      window.location.href = "/unlock";
    }, SESSION_TIMEOUT_MS);
  }

  if (stayBtn) {
    stayBtn.addEventListener("click", () => {
      resetTimers(true);
    });
  }

  window.onload = resetTimers;
}


// ===========================
// Flash Message Utility
// ===========================
function flashMessage(message, type) {
  const flash = document.createElement("div");
  flash.textContent = message;
  flash.style.position = "fixed";
  flash.style.top = "20px";
  flash.style.left = "50%";
  flash.style.transform = "translateX(-50%)";
  flash.style.backgroundColor = type === "error" ? "#f44336" : "#4CAF50";
  flash.style.color = "white";
  flash.style.padding = "10px 20px";
  flash.style.borderRadius = "5px";
  flash.style.zIndex = "1000";
  flash.style.boxShadow = "0 4px 6px rgba(0,0,0,0.1)";
  flash.style.fontWeight = "bold";
  flash.style.opacity = "0";
  flash.style.transition = "opacity 0.5s ease";
  document.body.appendChild(flash);

  setTimeout(() => {
    flash.style.opacity = "1";
  }, 10);

  setTimeout(() => {
    flash.style.opacity = "0";
    setTimeout(() => {
      flash.remove();
    }, 500);
  }, 2500);
}

// ===========================
// Save button password strength check
// ===========================

document.addEventListener("DOMContentLoaded", function () {
  handlePasswordStrength();
  handleThemeToggle();
  handleSidebarToggle();
  handleInactivityLock();
  handleFlashSessionExpiry();

  const saveButton = document.getElementById("saveButton");
  const signupButton = document.getElementById("signupButton");
  const editPasswordButton = document.getElementById("editPasswordButton");
  const passwordInput = document.getElementById("password");

  [saveButton, signupButton, editPasswordButton].forEach(button => {
    if (button) {
      button.addEventListener("click", function(event) {
        if (passwordInput) {
          const password = passwordInput.value;
          const strength = checkPasswordStrengthDirect(password);

          if (strength === "Weak") {
            event.preventDefault();
            flashMessage("Password too weak! Please choose a stronger password.", "error");
          }
        }
      });
    }
  });
});

// ===========================
// Close modal button
// ===========================
function closeModal() {
  const modal = document.getElementById("sessionModal");
  if (modal) modal.style.display = "none";
}