const menuButton = document.querySelector(".menu-button");
const mobileMenu = document.querySelector(".mobile-menu");

if (menuButton && mobileMenu) {
  menuButton.addEventListener("click", () => {
    const expanded = menuButton.getAttribute("aria-expanded") === "true";
    menuButton.setAttribute("aria-expanded", String(!expanded));
    mobileMenu.classList.toggle("open", !expanded);
  });
}

const form = document.querySelector("#contact-form");
const status = document.querySelector(".form-status");

if (form && status) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    status.textContent = "Sending...";
    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(Object.fromEntries(new FormData(form))),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || "Something went wrong.");
      form.reset();
      status.textContent = result.message;
    } catch (error) {
      status.textContent = error.message;
      status.style.color = "#c05656";
    } finally {
      button.disabled = false;
    }
  });
}
