/* Progressive enhancement. Content, instructions and links work without JS. */
(() => {
  const blocks = document.querySelectorAll(".code-block");
  blocks.forEach((block) => {
    const code = block.querySelector("pre code");
    const head = block.querySelector(".code-head");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-btn";
    button.textContent = "Copy";
    button.setAttribute("aria-label", `Copy ${block.querySelector("pre").getAttribute("aria-label") || "tool arguments"}`);
    button.setAttribute("aria-live", "polite");
    let reset;
    button.addEventListener("click", async () => {
      clearTimeout(reset);
      try {
        await navigator.clipboard.writeText(code.textContent);
        button.textContent = "Copied";
      } catch {
        // Clipboard permissions can be denied. Select the actual instructions
        // so keyboard users can still copy, rather than claiming success.
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        button.textContent = "Selected";
      }
      reset = setTimeout(() => { button.textContent = "Copy"; }, 1800);
    });
    head.appendChild(button);
  });

  document.querySelector(".processor-switch").hidden = false;
  document.querySelectorAll("[data-arch]").forEach((button) => {
    button.addEventListener("click", () => {
      const arch = button.dataset.arch;
      if (arch !== "arm64" && arch !== "amd64") return;
      document.querySelectorAll("[data-arch]").forEach((item) => {
        item.setAttribute("aria-pressed", String(item === button));
      });
      const binary = `sm-darwin-${arch}`;
      document.getElementById("download-code").textContent =
        `gh release download \\\n  -R karthikmprakash/agents-secret-manager \\\n  -p '${binary}*'\nshasum -a 256 -c ${binary}.sha256`;
      document.getElementById("install-code").textContent =
        `chmod +x ${binary}\nmkdir -p ~/.local/bin\nmv ${binary} ~/.local/bin/sm`;
    });
  });
})();
