/* Read-only build metadata. No model endpoint, evaluator, or visitor request form. */
(() => {
  "use strict";
  const target = document.getElementById("build-evidence");
  if (!target) return;
  fetch("https://anharmoniclabs.github.io/BULL/data/verification.json", { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("Evidence unavailable");
      return response.json();
    })
    .then((record) => {
      const commit = typeof record.commit === "string" ? record.commit.slice(0, 12) : "unknown";
      const suite = typeof record.pytest_summary === "string" ? record.pytest_summary : "See verification record";
      target.textContent = `GitHub publication ${commit}. Regression suite: ${suite}. Live deployment results above have their own pinned source.`;
    })
    .catch(() => { target.textContent = "Build metadata could not be loaded. Use the verification-record link below; no result is assumed."; });
})();

/* Progressive presentation: never hide core content or change evidence values. */
(() => {
  "use strict";
  document.querySelectorAll(".table-wrap").forEach((region) => {
    region.tabIndex = 0;
    region.setAttribute("role", "region");
    region.setAttribute("aria-label", region.querySelector("caption")?.textContent || "Scrollable engineering table");
  });
  if (!("IntersectionObserver" in window)) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      if (!reduced.matches) entry.target.classList.add("in-view");
      document.querySelectorAll(".masthead nav a").forEach((link) => {
        if (link.getAttribute("href") === `#${entry.target.id}`) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    });
  }, { rootMargin: "-10% 0px -55% 0px", threshold: 0 });
  document.querySelectorAll("main section[id]").forEach((section) => observer.observe(section));
})();
