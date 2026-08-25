/**
 * ADFIR Platform — Rules Section Controller
 */
const RulesList = {
  async load() {
    try {
      const data = await Api.getRules();
      this.renderTable(data.rules || []);
    } catch (err) {
      console.warn("Rules load failed:", err.message);
    }
  },

  renderTable(rules) {
    const tbody = document.getElementById("rules-body");
    if (!tbody) return;
    if (!rules.length) {
      tbody.innerHTML =
        '<tr class="table__empty-row"><td colspan="6">No rules loaded.</td></tr>';
      return;
    }
    tbody.innerHTML = rules
      .map(
        (r) =>
          `<tr>
            <td><code>${r.rule_id}</code></td>
            <td>${r.name}</td>
            <td>${r.rule_type}</td>
            <td>${r.severity_weight} / 10</td>
            <td>
              <span class="badge ${r.enabled ? "badge--p4" : "badge--p1"}">
                ${r.enabled ? "Enabled" : "Disabled"}
              </span>
            </td>
            <td>v${r.version}</td>
          </tr>`
      )
      .join("");
  },
};
