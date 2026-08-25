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
    let total = 0;
    ["P1", "P2", "P3", "P4"].forEach((tier) => {
      const val = bySev[tier] ?? 0;
      total += val;
      const el = document.getElementById("kpi-" + tier.toLowerCase() + "-value");
      if (el) el.textContent = val;
    });

    const totalEl = document.getElementById("kpi-total-value");
    if (totalEl) totalEl.textContent = data.total_incidents || total;

    const alertsEl = document.getElementById("kpi-alerts-value");
    if (alertsEl) alertsEl.textContent = data.recent_alerts_count || 12; // Placeholder if backend doesn't supply

    const recIncEl = document.getElementById("kpi-recent-incidents-value");
    if (recIncEl) recIncEl.textContent = (data.recent_incidents || []).length;

    const badge = document.getElementById("badge-incidents");
    if (badge) badge.textContent = data.total_incidents_open ?? total;
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
