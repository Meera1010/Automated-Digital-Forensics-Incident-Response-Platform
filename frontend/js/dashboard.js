/**
 * ADFIR Platform — Dashboard Controller
 * Loads KPI summary and recent incidents table.
 * TODO (Phase 6): Hook into live metrics chart.
 */
const Dashboard = {
  async load() {
    try {
      const data = await Api.getDashboardSummary();
      this.renderKpis(data);
      this.renderRecentIncidents(data.recent_incidents || []);
    } catch (err) {
      console.warn("Dashboard load failed:", err.message);
    }
  },

  renderKpis(data) {
    const bySev = data.incidents_by_severity || {};
    ["P1", "P2", "P3", "P4"].forEach((tier) => {
      const el = document.getElementById("kpi-" + tier.toLowerCase() + "-value");
      if (el) el.textContent = bySev[tier] ?? 0;
    });
    const evEl = document.getElementById("kpi-events-value");
    if (evEl) evEl.textContent = data.total_events_today ?? 0;
    const badge = document.getElementById("badge-incidents");
    if (badge) badge.textContent = data.total_incidents_open ?? 0;
  },

  renderRecentIncidents(incidents) {
    const tbody = document.getElementById("recent-incidents-body");
    if (!tbody) return;
    if (!incidents.length) {
      tbody.innerHTML =
        '<tr class="table__empty-row"><td colspan="6">No incidents found. Platform is standing by.</td></tr>';
      return;
    }
    tbody.innerHTML = incidents
      .map(
        (inc) =>
          `<tr data-incident-id="${inc.id}">
            <td><code>${inc.incident_number}</code></td>
            <td><span class="badge badge--${(inc.severity || "").toLowerCase()}">${inc.severity || "—"}</span></td>
            <td>${inc.status}</td>
            <td>${inc.attack_category || "—"}</td>
            <td>${inc.primary_asset_id || "—"}</td>
            <td>${new Date(inc.opened_at).toLocaleString()}</td>
          </tr>`
      )
      .join("");
  },
};
