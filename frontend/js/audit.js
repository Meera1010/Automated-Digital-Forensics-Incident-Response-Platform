/**
 * ADFIR Platform — Audit Log Section Controller
 */
const AuditLog = {
  async load() {
    try {
      const data = await Api.getAuditLog({ per_page: 50 });
      this.renderTable(data.audit_entries || []);
    } catch (err) {
      console.warn("Audit log load failed:", err.message);
    }
  },

  renderTable(entries) {
    const tbody = document.getElementById("audit-body");
    if (!tbody) return;
    if (!entries.length) {
      tbody.innerHTML =
        '<tr class="table__empty-row"><td colspan="6">No audit entries.</td></tr>';
      return;
    }
    tbody.innerHTML = entries
      .map(
        (e) =>
          `<tr>
            <td><code>#${e.id}</code></td>
            <td style="font-family:var(--font-mono);font-size:0.75rem">
              ${new Date(e.logged_at).toISOString()}
            </td>
            <td>${e.actor_id}</td>
            <td>${e.module}</td>
            <td>${e.action}</td>
            <td>${
              e.target_type
                ? e.target_type + ":" + (e.target_id ? e.target_id.slice(0, 8) + "…" : "")
                : "—"
            }</td>
          </tr>`
      )
      .join("");
  },
};

document.getElementById("btn-verify-chain")?.addEventListener("click", async () => {
  const resultEl = document.getElementById("chain-verify-result");
  resultEl.className = "alert";
  resultEl.textContent = "Verifying chain integrity…";
  try {
    const result = await Api.verifyAuditChain();
    resultEl.className = "alert " + (result.valid ? "alert--success" : "alert--error");
    resultEl.textContent = result.valid
      ? `✓ Chain intact — ${result.total_rows} entries verified.`
      : `✗ Chain broken at entry #${result.first_broken_id}. Manual review required.`;
  } catch (err) {
    resultEl.className = "alert alert--error";
    resultEl.textContent = "Verification failed: " + err.message;
  }
});
