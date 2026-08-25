/**
 * ADFIR Platform — Reports Section Controller
 */
const ReportsList = {
  async load() {
    try {
      const data = await Api.getReports();
      this.renderTable(data.reports || []);
    } catch (err) {
      console.warn("Reports load failed:", err.message);
    }
  },

  renderTable(reports) {
    const tbody = document.getElementById("reports-body");
    if (!tbody) return;
    if (!reports.length) {
      tbody.innerHTML =
        '<tr class="table__empty-row"><td colspan="6">No reports generated.</td></tr>';
      return;
    }
    tbody.innerHTML = reports
      .map(
        (r) =>
          `<tr>
            <td>${r.title}</td>
            <td><code>${r.incident_id ? r.incident_id.slice(0, 8) + "…" : "—"}</code></td>
            <td><span class="badge badge--info">${r.format.toUpperCase()}</span></td>
            <td>${new Date(r.generated_at).toLocaleString()}</td>
            <td><code style="font-size:0.7rem">
              ${r.sha256_hash ? r.sha256_hash.slice(0, 16) + "…" : "—"}
            </code></td>
            <td>
              <a class="btn btn--ghost btn--sm"
                href="/api/v1/reports/${r.id}/download"
                target="_blank">Download</a>
            </td>
          </tr>`
      )
      .join("");
  },
};
