/**
 * ADFIR Platform — API Client (api.js)
 * =====================================
 * Thin wrapper around the native fetch API for all /api/v1/ calls.
 * Handles: JWT token attachment, response envelope unwrapping,
 * error propagation, and automatic 401 redirect to login.
 *
 * TODO (Phase 6): Implement all methods below.
 */

const API_BASE = "/api/v1";

// Token storage key in sessionStorage (cleared on tab close).
const TOKEN_KEY = "adfir_token";

const Api = {

  // --- Auth helpers --------------------------------------------------------

  setToken(token) { sessionStorage.setItem(TOKEN_KEY, token); },
  getToken()      { return sessionStorage.getItem(TOKEN_KEY); },
  clearToken()    { sessionStorage.removeItem(TOKEN_KEY); },
  isAuthenticated() { return !!this.getToken(); },

  // --- Core fetch wrapper --------------------------------------------------

  async _request(method, path, body = null) {
    const headers = { "Content-Type": "application/json" };
    const token = this.getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const response = await fetch(`${API_BASE}${path}`, opts);

    // Handle authentication expiry.
    if (response.status === 401) {
      this.clearToken();
      window.App?.showLogin();
      throw new Error("Session expired — please log in again.");
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message = data?.error?.message || `HTTP ${response.status}`;
      throw new Error(message);
    }

    return data;
  },

  get(path)          { return this._request("GET",    path); },
  post(path, body)   { return this._request("POST",   path, body); },
  put(path, body)    { return this._request("PUT",    path, body); },
  patch(path, body)  { return this._request("PATCH",  path, body); },

  // --- Auth endpoints ------------------------------------------------------

  async login(username, password) {
    const data = await this.post("/auth/login", { username, password });
    this.setToken(data.access_token);
    return data.user;
  },

  async logout() {
    await this.post("/auth/logout");
    this.clearToken();
  },

  async me()        { return this.get("/auth/me"); },

  // --- Dashboard -----------------------------------------------------------

  async getDashboardSummary() { return this.get("/dashboard/summary"); },
  async getDashboardMetrics(period = "24h") {
    return this.get(`/dashboard/metrics?period=${period}`);
  },

  // --- Events --------------------------------------------------------------

  async getEvents(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.get(`/events${qs ? "?" + qs : ""}`);
  },

  async ingestEvent(payload) { return this.post("/events/ingest", payload); },

  // --- Incidents -----------------------------------------------------------

  async getIncidents(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.get(`/incidents${qs ? "?" + qs : ""}`);
  },

  async getIncident(id)       { return this.get(`/incidents/${id}`); },
  async getTimeline(id)       { return this.get(`/incidents/${id}/timeline`); },
  async getIncidentEvidence(id) { return this.get(`/incidents/${id}/evidence`); },
  async getIncidentActions(id)  { return this.get(`/incidents/${id}/actions`); },
  async closeIncident(id)     { return this.post(`/incidents/${id}/close`); },
  async triggerReport(id, format = "html") {
    return this.post(`/incidents/${id}/reports?format=${format}`);
  },

  // --- Evidence ------------------------------------------------------------

  async getArtifact(id)       { return this.get(`/evidence/${id}`); },
  async verifyArtifact(id)    { return this.get(`/evidence/${id}/verify`); },

  // --- Rules ---------------------------------------------------------------

  async getRules()             { return this.get("/rules"); },
  async toggleRule(id)         { return this.patch(`/rules/${id}/toggle`); },

  // --- Playbooks -----------------------------------------------------------

  async getPlaybooks()         { return this.get("/playbooks"); },

  // --- Reports -------------------------------------------------------------

  async getReports()           { return this.get("/reports"); },
  async getReport(id)          { return this.get(`/reports/${id}`); },

  // --- Audit ---------------------------------------------------------------

  async getAuditLog(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this.get(`/audit${qs ? "?" + qs : ""}`);
  },
  async verifyAuditChain()    { return this.get("/audit/verify"); },
};

// Expose globally.
window.Api = Api;
