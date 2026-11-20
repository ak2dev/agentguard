// The /signin/ page: starts Google or GitHub sign-in (public/js/account.js does the work) and shows
// errors from a sign-in that came back without a session.
const account = window.agentguardAccount;
const $ = (id) => document.getElementById(id);
if (account?.enabled) main();

async function main() {
  const buttons = [...document.querySelectorAll("[data-oauth]")];
  const errorBox = $("signin-error");
  const showError = (msg) => { errorBox.textContent = msg; errorBox.hidden = !msg; };

  const result = await account.ready;
  const err = account.takeSignInError() || result?.error;
  if (err) showError(`Sign-in did not complete: ${err}`);

  function render(u) {
    $("signin-done").hidden = !u;
    if (u) $("signin-who").textContent = u.email || u.name;
  }
  render(account.user());
  account.onChange(render);

  for (const button of buttons) {
    button.disabled = false;
    button.addEventListener("click", async () => {
      showError("");
      for (const b of buttons) b.disabled = true;
      button.setAttribute("aria-busy", "true");
      try {
        await account.signIn(button.dataset.oauth, {
          next: new URLSearchParams(location.search).get("next"),
          remember: $("signin-remember").checked,
        });
      } catch (e) {
        showError(e.message || String(e));
        for (const b of buttons) b.disabled = false;
        button.removeAttribute("aria-busy");
      }
    });
  }

  $("signin-out").addEventListener("click", () => account.signOut());
}
