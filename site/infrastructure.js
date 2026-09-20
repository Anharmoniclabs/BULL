/* Read-only build metadata. No model endpoint, evaluator, or visitor request form. */
(() => {
  "use strict";
  const target = document.getElementById("build-evidence");
  if (!target) return;
  fetch("./data/verification.json", { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("Evidence unavailable");
      return response.json();
    })
    .then((record) => {
      const commit = typeof record.commit === "string" ? record.commit.slice(0, 12) : "unknown";
      const suite = typeof record.pytest_summary === "string" ? record.pytest_summary : "See verification record";
      target.textContent = `Published commit ${commit}. Regression suite: ${suite}. Hardware boot certification is separate.`;
    })
    .catch(() => { target.textContent = "Build metadata could not be loaded. Use the verification-record link below; no result is assumed."; });
})();
