/**
 * ADFIR Platform — Main Application Controller (app.js)
 * ======================================================
 * Bootstraps the SPA: handles routing, auth gating, clock,
 * and polling lifecycle.  Loaded last so all other scripts
 * are available.
 *
 * TODO (Phase 6): Implement full SPA routing and polling.
 */

const App = {

  // Polling interval for live data refresh (milliseconds).
  POLL_INTERVAL_MS: 5000,
  _pollTimer: null,
  _currentSection: "dashboard",

  // -----------------------------------------------------------------------
  init() {
    this.bindNavigation();
    this.bindLoginForm();
    this.bindLogout();
    this.startClock();
    this.bindDetailPanel();

    if (Api.isAuthenticated()) {
      this.showApp();
    } else {
      this.showLogin();
    }
  },

  // -----------------------------------------------------------------------
  showLogin() {
    document.getElementById("section-login").classList.remove("app-wrapper--hidden");
    document.getElementById("app-wrapper").classList.add("app-wrapper--hidden");
    this.stopPolling();
  },

  async showApp() {
    document.getElementById("section-login").classList.add("app-wrapper--hidden");
    document.getElementById("app-wrapper").classList.remove("app-wrapper--hidden");
    try {
      const user = await Api.me();
      this.setCurrentUser(user);
    } catch {
      this.showLogin();
      return;
    }
    this.navigateTo(this._currentSection);
    this.startPolling();
  },

  setCurrentUser(user) {
    const name = user?.user_id || "Analyst";
    document.getElementById("user-name").textContent = name;
  },

  // -----------------------------------------------------------------------
  bindLoginForm() {
    document.getElementById("login-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById("login-error");
      const btn = document.getElementById("btn-login");
      errorEl.textContent = "";
      btn.textContent = "Signing in…";
      btn.disabled = true;
      try {
        const username = document.getElementById("input-username").value.trim();
        const password = document.getElementById("input-password").value;
        await Api.login(username, password);
        await this.showApp();
      } catch (err) {
        errorEl.textContent = err.message || "Login failed. Please try again.";
      } finally {
        btn.textContent = "Sign In";
        btn.disabled = false;
      }
    });
  },

  // -----------------------------------------------------------------------
  bindLogout() {
    document.getElementById("btn-logout")?.addEventListener("click", async () => {
      try { await Api.logout(); } catch { /* ignore */ }
      Api.clearToken();
      this.showLogin();
    });
  },

  // -----------------------------------------------------------------------
  bindNavigation() {
    document.querySelectorAll("[data-section]").forEach((el) => {
      el.addEventListener("click", (e) => {
        const section = el.dataset.section;
        if (section) {
          e.preventDefault();
          this.navigateTo(section);
        }
      });
    });
  },

  navigateTo(section) {
    this._currentSection = section;

    // Update active nav item.
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.classList.toggle("nav-item--active", el.dataset.section === section);
      if (el.dataset.section === section) el.setAttribute("aria-current", "page");
      else el.removeAttribute("aria-current");
    });

    // Show/hide sections.
    document.querySelectorAll(".page-section").forEach((el) => {
      el.classList.toggle("page-section--hidden", el.dataset.section !== section);
    });

    // Update page title.
    const titles = {
      dashboard:    ["Dashboard", "Live threat overview"],
      incidents:    ["Incidents", "All detected incidents"],
      alerts:       ["Alerts Stream", "Live raw event feed"],
      evidence:     ["Evidence", "Collected artifacts"],
      verification: ["Evidence Verification", "Cryptographic integrity checks"],
      rules:        ["Detection Rules", "Rule library"],
      responses:    ["Automated Responses", "Execution playbooks"],
      reports:      ["Reports", "Forensic reports"],
      audit:        ["Audit Log", "Immutable action trail"],
      status:       ["System Status", "Platform health & telemetry"],
    };
    const [title, sub] = titles[section] || ["ADFIR", ""];
    document.getElementById("page-title").textContent = title;
    document.getElementById("page-subtitle").textContent = sub;

    // Trigger section-specific data load.
    this.loadSection(section);
  },

  async loadSection(section) {
    if (!Api.isAuthenticated()) return;
    try {
      switch (section) {
        case "dashboard": await Dashboard.load(); break;
        case "incidents": await IncidentsList.load(); break;
        case "alerts":    await AlertsStream.load(); break;
        case "evidence":  await EvidenceList.load(); break;
        case "verification": await VerificationList.load(); break;
        case "rules":     await RulesList.load(); break;
        case "responses": await ResponsesList.load(); break;
        case "reports":   await ReportsList.load(); break;
        case "audit":     await AuditLog.load(); break;
        case "status":    await SystemStatus.load(); break;
      }
    } catch (err) {
      console.warn(`Failed to load section "${section}":`, err.message);
    }
  },

  // -----------------------------------------------------------------------
  startPolling() {
    this.stopPolling();
    this._pollTimer = setInterval(() => {
      this.loadSection(this._currentSection);
    }, this.POLL_INTERVAL_MS);
  },

  stopPolling() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
  },

  // -----------------------------------------------------------------------
  startClock() {
    const el = document.getElementById("topbar-clock");
    const tick = () => {
      el.textContent = new Date().toUTCString().replace(/.*(\d{2}:\d{2}:\d{2}).*/, "$1 UTC");
    };
    tick();
    setInterval(tick, 1000);
  },

  // -----------------------------------------------------------------------
  bindDetailPanel() {
    const panel   = document.getElementById("detail-panel");
    const overlay = document.getElementById("overlay");
    const closeBtn = document.getElementById("btn-close-detail");

    const close = () => {
      panel.classList.remove("detail-panel--open");
      overlay.classList.remove("overlay--visible");
      panel.setAttribute("aria-hidden", "true");
    };

    closeBtn?.addEventListener("click", close);
    overlay?.addEventListener("click", close);
  },

  openDetailPanel(title, htmlContent) {
    const panel   = document.getElementById("detail-panel");
    const overlay = document.getElementById("overlay");
    document.getElementById("detail-panel-title").textContent = title;
    document.getElementById("detail-panel-body").innerHTML = htmlContent;
    panel.classList.add("detail-panel--open");
    overlay.classList.add("overlay--visible");
    panel.removeAttribute("aria-hidden");
  },
};

// -------------------------------------------------------------------------
// Stub module objects — will be replaced by section-specific scripts.
// -------------------------------------------------------------------------

const Dashboard        = { load: async () => {} };
const IncidentsList    = { load: async () => {} };
const AlertsStream     = { load: async () => {} };
const EvidenceList     = { load: async () => {} };
const VerificationList = { load: async () => {} };
const RulesList        = { load: async () => {} };
const ResponsesList    = { load: async () => {} };
const ReportsList      = { load: async () => {} };
const AuditLog         = { load: async () => {} };
const SystemStatus     = { load: async () => {} };

// Expose globally for cross-module access.
window.App = App;

// Bootstrap when DOM is ready.
document.addEventListener("DOMContentLoaded", () => App.init());
