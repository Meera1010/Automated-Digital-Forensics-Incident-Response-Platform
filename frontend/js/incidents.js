/**
 * ADFIR Platform — Incidents Section Controller
 * Loads and renders the incidents table with filters.
 */
const IncidentsList = {
  async load() {
    const status = document.getElementById("filter-status")?.value || "";
    const severity = document.getElementById("filter-severity")?.value || "";
    const params = {};
    if (status) params.status = status;
    if (severity) params.severity = severity;
    try {
      const data = await Api.getIncidents(params);
      this.renderTable(data.incidents || []);
    } catch (err) {
      console.warn("Incidents load failed:", err.message);
    }
  },

  renderTable(incidents) {
    const tbody = document.getElementById("incidents-body");
    if (!tbody) return;
    if (!incidents.length) {
      tbody.innerHTML =
        '<tr class="table__empty-row"><td colspan="9">No incidents yet.</td></tr>';
      return;
    }
    tbody.innerHTML = incidents
      .map(
        (inc) =>
          `<tr>
            <td><code>${inc.incident_number}</code></td>
            <td><span class="badge badge--${(inc.severity || "").toLowerCase()}">${inc.severity || "—"}</span></td>
            <td>${inc.status}</td>
            <td>${inc.attack_category || "—"}</td>
            <td>${inc.primary_asset_id || "—"}</td>
            <td>${inc.evidence_count ?? 0}</td>
            <td>${inc.action_count ?? 0}</td>
            <td>${new Date(inc.opened_at).toLocaleString()}</td>
            <td>
              <button class="btn btn--ghost btn--sm"
                onclick="IncidentsList.openDetail('${inc.id}')">View</button>
            </td>
          </tr>`
      )
      .join("");
  },

  async openDetail(id) {
    try {
      const inc = await Api.getIncident(id);
      const html = `<pre style="white-space:pre-wrap;font-size:0.78rem;
        color:var(--color-text-secondary)">${JSON.stringify(inc, null, 2)}</pre>`;
      window.App.openDetailPanel("Incident " + (inc.incident_number || id), html);
    } catch (err) {
      console.warn("Failed to load incident detail:", err.message);
    }
  },
};

// Re-load on filter change.
document.getElementById("filter-status")?.addEventListener("change", () => IncidentsList.load());
document.getElementById("filter-severity")?.addEventListener("change", () => IncidentsList.load());
