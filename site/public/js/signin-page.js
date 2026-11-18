// The /signin/ page: starts Google sign-in (public/js/account.js does the work) and shows
// errors from a sign-in that came back without a session.
const account = window.agentguardAccount;
const $ = (id) => document.getElementById(id);
if (account?.enabled) main();

async function main() {
  const google = document.querySelector('[data-oauth="google"]');
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

  google.disabled = false;
  google.addEventListener("click", async () => {
    showError("");
    google.disabled = true;
    google.setAttribute("aria-busy", "true");
    try {
      await account.signIn("google", {
        next: new URLSearchParams(location.search).get("next"),
        remember: $("signin-remember").checked,
      });
    } catch (e) {
      showError(e.message || String(e));
      google.disabled = false;
      google.removeAttribute("aria-busy");
    }
  });

  $("signin-out").addEventListener("click", () => account.signOut());
  $("signin-form").addEventListener("submit", (e) => e.preventDefault());
}
