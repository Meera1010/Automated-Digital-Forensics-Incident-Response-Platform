/**
 * ADFIR Platform — Evidence Section Controller
 * Evidence is shown per-incident; this stub satisfies the module contract.
 * TODO (Phase 6): Implement global evidence list view.
 */
const EvidenceList = {
  async load() {
    // The evidence table is populated per-incident from the detail panel.
    // Global evidence listing will be implemented in Phase 6.
    const tbody = document.getElementById("evidence-body");
    if (tbody) {
      tbody.innerHTML =
        '<tr class="table__empty-row"><td colspan="6">Select an incident to view its evidence artifacts.</td></tr>';
    }
  },
};
