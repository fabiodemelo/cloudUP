/* CloudUp — free license screen (direct-download build only).
 *
 * Covers the whole window until this Mac has a valid license: email -> the
 * 6-digit code we send -> the email's key, or a pasted key. The Mac App Store
 * build has no license commands, so `license_status` fails there and the
 * screen never shows. Uses invoke(), listen(), el() and toast() from app.js. */

const lic = { email: "", resolve: null, root: null };

/** Resolves once CloudUp may be used. */
async function licenseGate() {
  let st;
  try { st = await invoke("license_status"); }
  catch (e) { return; } // no license in this build
  if (st.state === "licensed") return;
  await new Promise((resolve) => { lic.resolve = resolve; showLicense(st); });
}

/** The background check found the license gone: lock the window again. */
function initLicenseWatch() {
  listen("license-changed", async () => {
    let st;
    try { st = await invoke("license_status"); } catch (e) { return; }
    if (st.state === "licensed") { hideLicense(); return; }
    if (!lic.root) showLicense(st);
  }).catch(() => {});
}

function showLicense(st) {
  if (!lic.root) {
    lic.root = el("div", "lic");
    lic.root.setAttribute("role", "dialog");
    lic.root.setAttribute("aria-modal", "true");
    lic.root.setAttribute("aria-labelledby", "lic-title");
    const card = el("div", "lic-card");
    const logo = el("img", "lic-logo");
    logo.src = "icons/logo.png";
    logo.alt = "CloudUp";
    card.append(logo, el("h1", null), el("p", "lic-sub"), el("div", "lic-body"));
    card.querySelector("h1").id = "lic-title";
    lic.root.append(card);
    document.body.append(lic.root);
    document.getElementById("app").setAttribute("inert", "");
  }
  licenseScreen("email", st && st.message);
}

function hideLicense() {
  if (lic.root) lic.root.remove();
  lic.root = null;
  document.getElementById("app").removeAttribute("inert");
  if (lic.resolve) { const r = lic.resolve; lic.resolve = null; r(); }
}

async function licensed(st) {
  hideLicense();
  toast("CloudUp is activated on this Mac." + (st && st.email ? " License: " + st.email : ""), 4000);
  // Drives marked "mount automatically" mount now; refresh their state shortly.
  if (typeof refreshMountsQuiet === "function") setTimeout(refreshMountsQuiet, 2500);
}

// ---- building blocks
function licField(form, label, opts) {
  const id = "lic-" + opts.name;
  const l = el("label", "field-label", label);
  l.htmlFor = id;
  const i = document.createElement("input");
  Object.assign(i, { id, type: opts.type || "text", name: opts.name, spellcheck: false, autocomplete: opts.autocomplete || "off" });
  if (opts.placeholder) i.placeholder = opts.placeholder;
  if (opts.value) i.value = opts.value;
  if (opts.inputmode) i.inputMode = opts.inputmode;
  if (opts.maxLength) i.maxLength = opts.maxLength;
  if (opts.cls) i.className = opts.cls;
  form.append(l, i);
  return i;
}

function licLink(label, onClick) {
  const b = el("button", "lic-link", label);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

// Run `fn` with `btn` busy; a thrown error goes to `err`.
async function licRun(btn, busyLabel, err, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = busyLabel;
  err.textContent = "";
  try { await fn(); }
  catch (e) { err.textContent = (e && e.message) || String(e); }
  finally { btn.disabled = false; btn.textContent = old; }
}

function licenseScreen(name, message) {
  const card = lic.root.querySelector(".lic-card");
  const body = card.querySelector(".lic-body");
  body.innerHTML = "";
  const err = el("p", "lic-error");
  err.setAttribute("role", "alert");
  if (message) err.textContent = message;
  const form = el("form", "conn-form lic-form");
  form.noValidate = true;
  const submit = el("button", "btn primary");
  submit.type = "submit";
  const links = el("div", "lic-links");
  const head = (title, sub) => {
    card.querySelector("h1").textContent = title;
    card.querySelector(".lic-sub").textContent = sub;
  };

  if (name === "email") {
    head("Activate CloudUp", "CloudUp is free. Enter your email and we'll send you a 6-digit code to activate it on this Mac.");
    const email = licField(form, "Email", { name: "email", type: "email", autocomplete: "email", value: lic.email, placeholder: "you@example.com" });
    submit.textContent = "Email me a code";
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      licRun(submit, "Sending…", err, async () => {
        const v = email.value.trim();
        if (!v || !v.includes("@")) throw new Error("Enter your email address.");
        await invoke("license_request_code", { email: v });
        lic.email = v;
        licenseScreen("code");
      });
    });
    links.append(licLink("I have a license key", () => licenseScreen("key")));
  } else if (name === "code") {
    head("Check your email", "Enter the 6-digit code we sent to " + lic.email + ". It expires in 30 minutes.");
    const code = licField(form, "Code", { name: "code", inputmode: "numeric", autocomplete: "one-time-code", maxLength: 6, placeholder: "000000", cls: "lic-code" });
    submit.textContent = "Activate";
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      licRun(submit, "Activating…", err, async () => {
        try {
          await licensed(await invoke("license_verify_code", { email: lic.email, code: code.value }));
        } catch (e) {
          // The key came back but didn't activate: retry from the key screen.
          const msg = (e && e.message) || String(e);
          if (msg.includes("license key is saved")) { licenseScreen("key", msg); return; }
          throw e;
        }
      });
    });
    links.append(
      licLink("Send a new code", () => licRun(submit, "Sending…", err, async () => {
        await invoke("license_request_code", { email: lic.email });
        toast("We sent a new code to " + lic.email + ".");
      })),
      licLink("Use a different email", () => licenseScreen("email")),
    );
  } else {
    head("Enter your license key", "It's in the email we sent when you downloaded CloudUp. One license works on up to 5 Macs.");
    const key = licField(form, "License key", { name: "key", placeholder: "DM-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", cls: "lic-key" });
    invoke("license_saved_key").then((k) => { if (k && !key.value) key.value = k; }).catch(() => {});
    submit.textContent = "Activate";
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      licRun(submit, "Activating…", err, async () => {
        const st = await invoke("license_activate", { key: key.value });
        await licensed(st);
      });
    });
    links.append(licLink("Get it by email instead", () => licenseScreen("email")));
  }

  const actions = el("div", "form-actions lic-actions");
  actions.append(el("span", "form-spacer"), submit);
  form.append(actions);
  body.append(form, err, links);
  const first = form.querySelector("input");
  if (first) first.focus();
}
