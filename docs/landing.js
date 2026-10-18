/* sm landing page: progressive enhancement only. No external requests. */

document.documentElement.classList.add("js");

// Reveal sections as they enter the viewport. IntersectionObserver, not scroll.
(function () {
  const items = document.querySelectorAll(".reveal");
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce || !("IntersectionObserver" in window)) {
    items.forEach((item) => item.classList.add("in"));
    return;
  }
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      });
    },
    { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
  );
  items.forEach((item) => observer.observe(item));
})();

// Copy buttons for every code block.
(function () {
  document.querySelectorAll("pre").forEach((pre) => {
    const text = pre.innerText;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-btn";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy code");
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
      } catch (error) {
        button.textContent = "Select";
      }
      window.setTimeout(() => {
        button.textContent = "Copy";
      }, 1400);
    });
    pre.appendChild(button);
  });
})();
