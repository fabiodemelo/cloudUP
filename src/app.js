/* CloudUp — frontend logic */

// ---------------------------------------------------------------- IPC bridge
const T = window.__TAURI_INTERNALS__;
async function invoke(cmd, args) {
  return T.invoke(cmd, args || {});
}
function winLabel() {
  try { return T.metadata.currentWindow.label; } catch (e) { return "main"; }
}
async function setWindowTitle(title) {
  try { await invoke("plugin:window|set_title", { label: winLabel(), value: title }); } catch (e) {}
}

// ------------------------------------------------------------------- config

// Grid tile list. `type` is the grid key; the Rust serde name is resolved via
// the SERDE map below. Types the backend doesn't report as functional (Mega,
// which needs an external command-line tool) are left out of the grid.
const TYPES = [
  { type: "s3",        label: "Amazon S3",       icon: "icons/s3.png" },
  { type: "backblaze", label: "Backblaze B2",    icon: "icons/backblaze.png" },
  { type: "webdav",    label: "WebDAV",          icon: "icons/webdav.png" },
  { type: "openstack", label: "OpenStack Swift", icon: "icons/openstack.png" },
  { type: "ftp",       label: "FTP",             icon: "icons/ftp.png" },
  { type: "sftp",      label: "SFTP",            icon: "icons/ftp.png" },
  { type: "pcloud",    label: "pCloud",          icon: "icons/pcloud.png" },
  { type: "dropbox",   label: "Dropbox",         icon: "icons/dropbox.png" },
  { type: "gdrive",    label: "Google Drive",    icon: "icons/gdrive.png" },
  { type: "onedrive",  label: "OneDrive",        icon: "icons/onedrive.png" },
  { type: "box",       label: "Box",             icon: "icons/box.png" },
  { type: "mega",      label: "Mega",            icon: "icons/mega.png" },
];

// Grid key -> Rust serde `ConnType` name. `gdrive` is the one that differs from
// the grid key (Rust calls it `googledrive`); the rest are identity. Used for
// the functional check, for `conn.type`, and to look up an icon by type.
const SERDE = {
  s3: "s3", backblaze: "backblaze", webdav: "webdav", openstack: "openstack",
  ftp: "ftp", sftp: "sftp", pcloud: "pcloud",
  dropbox: "dropbox", gdrive: "googledrive", onedrive: "onedrive", box: "box", mega: "mega",
};

// serde name -> grid key (for saved connections shown in the sidebar).
function connTypeKey(ctype) {
  for (const k in SERDE) if (SERDE[k] === ctype) return k;
  return ctype;
}

// Per-type metadata: endpoint/region defaults (pre-fill + placeholder) and
// whether the type authenticates via an OAuth2 PKCE browser flow.
const CONN = {
  s3:        { endpoint: "https://s3.amazonaws.com",            region: "us-east-1" },
  backblaze: { endpoint: "https://s3.us-west-0.backblazeb2.com", region: "us-west-0" },
  webdav:    { endpoint: "https://example.com/remote" },
  openstack: { endpoint: "https://auth.example.com/v3" },
  ftp:       { endpoint: "ftp.example.com" },
  sftp:      { endpoint: "sftp.example.com" },
  mega:      { endpoint: "https://mega.nz" },
  pcloud:    { endpoint: "https://api.pcloud.com" },
  dropbox:   { oauth: true },
  gdrive:    { oauth: true },
  onedrive:  { oauth: true },
  box:       { oauth: true },
};

// Field descriptors per type. Shape: { key, label, type?, placeholder?, field?, pick? }
//   - `field: true` -> the value goes into `conn.fields[key]` (provider extra).
//   - `pick: true`  -> a "Choose…" button next to the field opens the file picker.
// The `bucket` key is the place the connection opens at: "Bucket" for the
// S3-style services, "Container" for Swift, "Folder ID" for Google Drive
// (which addresses folders by id) and "Folder" everywhere else.
//   - key `secret`  -> a pseudo-field -> the separate `secret` command arg.
//   - everything else maps to a top-level `Connection` field.
const FORMS = {
  s3: [
    { key: "name",       label: "Name" },
    { key: "access_key", label: "Access Key ID" },
    { key: "secret",     label: "Secret Access Key", type: "password" },
    { key: "endpoint",   label: "S3 endpoint", placeholder: "https://s3.amazonaws.com" },
    { key: "region",     label: "Region", placeholder: "us-east-1" },
    { key: "bucket",     label: "Bucket", placeholder: "my-bucket" },
  ],
  backblaze: [
    { key: "name",       label: "Name" },
    { key: "access_key", label: "Application Key ID" },
    { key: "secret",     label: "Application Key", type: "password" },
    { key: "endpoint",   label: "Endpoint", placeholder: "https://s3.us-west-0.backblazeb2.com" },
    { key: "region",     label: "Region", placeholder: "us-west-0" },
    { key: "bucket",     label: "Bucket", placeholder: "my-bucket" },
  ],
  webdav: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "WebDAV URL", placeholder: "https://example.com/remote" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Folder", placeholder: "/" },
  ],
  openstack: [
    { key: "name",           label: "Name" },
    { key: "endpoint",       label: "Auth URL", placeholder: "https://auth.example.com/v3" },
    { key: "access_key",     label: "Username" },
    { key: "secret",         label: "Password", type: "password" },
    { key: "user_domain",    label: "User domain",  field: true, placeholder: "Default" },
    { key: "project_domain", label: "Project domain", field: true, placeholder: "Default" },
    { key: "project",        label: "Project", field: true, placeholder: "my-project" },
    { key: "bucket",         label: "Container", placeholder: "/" },
  ],
  ftp: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "Host", placeholder: "ftp.example.com" },
    { key: "port",       label: "Port", field: true, placeholder: "21" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Folder", placeholder: "/" },
  ],
  sftp: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "Host", placeholder: "sftp.example.com" },
    { key: "port",       label: "Port", field: true, placeholder: "22" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "key",        label: "Private key file (optional)", field: true, placeholder: "~/.ssh/id_ed25519", pick: true },
    { key: "bucket",     label: "Folder", placeholder: "/" },
  ],
  mega: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "Host", placeholder: "https://mega.nz" },
    { key: "access_key", label: "Email" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Folder", placeholder: "/" },
  ],
  pcloud: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "API host", placeholder: "https://api.pcloud.com" },
    { key: "access_key", label: "Username (email)" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Folder", placeholder: "/" },
  ],
  dropbox: [
    { key: "name",          label: "Name" },
    { key: "client_id",     label: "Client ID", field: true },
    { key: "client_secret", label: "Client Secret", field: true, type: "password" },
    { key: "bucket",        label: "Folder", placeholder: "/" },
  ],
  gdrive: [
    { key: "name",          label: "Name" },
    { key: "client_id",     label: "Client ID", field: true },
    { key: "client_secret", label: "Client Secret", field: true, type: "password" },
    { key: "bucket",        label: "Folder ID", placeholder: "root" },
  ],
  onedrive: [
    { key: "name",          label: "Name" },
    { key: "client_id",     label: "Client ID (App ID)", field: true },
    { key: "client_secret", label: "Client Secret", field: true, type: "password" },
    { key: "bucket",        label: "Folder", placeholder: "/" },
  ],
  box: [
    { key: "name",          label: "Name" },
    { key: "client_id",     label: "Client ID", field: true },
    { key: "client_secret", label: "Client Secret", field: true, type: "password" },
    { key: "bucket",        label: "Folder", placeholder: "/" },
  ],
};


// -------------------------------------------------------------------- state
const state = {
  connections: [],
  functional: new Set(),      // serde names from functional_types()
  view: "empty",              // grid | form | browser | empty
  selectedType: null,         // grid key while in the form
  editingId: null,            // connection id being edited (null = new)
  formIsNew: true,            // the form was opened to add (not edit) a connection
  selectedConnId: null,       // connection shown in the browser / sidebar
  browserPath: "/",
  selectedEntry: null,        // { name, path, is_dir, size }
  mounts: [],                 // raw list_mounted() result
  mounted: new Set(),         // ids currently mounted as drives
  mountAvailable: false,
  mountNote: "",
  _lastEntries: null,         // listing shown for browserPath (null while loading)
  browseSeq: 0,               // bumps on every browse; stale responses are dropped
  previewEntry: null,         // file open in the preview modal
  _fileText: null,            // decoded text of the file open in the modal
  draggingOut: false,         // a drag from our own list is in progress
  showHidden: loadPref("showHidden") === "1", // dot-files are hidden by default
};

function loadPref(k) { try { return localStorage.getItem("cloudup." + k); } catch (e) { return null; } }
function savePref(k, v) { try { localStorage.setItem("cloudup." + k, v); } catch (e) {} }

// ---------------------------------------------------------------------- icons
// Line icons in the style of SF Symbols; they inherit the button's colour.
const svg = (body) => '<svg class="ico" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + body + "</svg>";
const ICONS = {
  plus: svg('<path d="M10 4.5v11M4.5 10h11"/>'),
  minus: svg('<path d="M4.5 10h11"/>'),
  pencil: svg('<path d="M12.8 4.2l3 3L7.6 15.4l-3.7.7.7-3.7z"/><path d="M11.3 5.7l3 3"/>'),
  up: svg('<path d="M10 15.5v-11M5.5 9L10 4.5 14.5 9"/>'),
  refresh: svg('<path d="M15.6 8.2A5.8 5.8 0 0 0 4.9 7"/><path d="M4.4 11.8A5.8 5.8 0 0 0 15.1 13"/><path d="M15.8 4.2v4h-4M4.2 15.8v-4h4"/>'),
  upload: svg('<path d="M10 12.5V3.5M6.5 7L10 3.5 13.5 7"/><path d="M3.5 12v2.6c0 .8.6 1.4 1.4 1.4h10.2c.8 0 1.4-.6 1.4-1.4V12"/>'),
  download: svg('<path d="M10 3.5v9M6.5 9L10 12.5 13.5 9"/><path d="M3.5 12v2.6c0 .8.6 1.4 1.4 1.4h10.2c.8 0 1.4-.6 1.4-1.4V12"/>'),
  "folder-plus": svg('<path d="M2.8 5.6c0-.8.6-1.4 1.4-1.4h3.2l1.6 1.6h6.8c.8 0 1.4.6 1.4 1.4v7c0 .8-.6 1.4-1.4 1.4H4.2c-.8 0-1.4-.6-1.4-1.4z"/><path d="M10 8.5v4.5M7.75 10.75h4.5"/>'),
  trash: svg('<path d="M3.8 5.5h12.4M8 5.5V4c0-.4.3-.7.7-.7h2.6c.4 0 .7.3.7.7v1.5"/><path d="M5.3 5.5l.7 10c0 .7.6 1.2 1.2 1.2h5.6c.6 0 1.2-.5 1.2-1.2l.7-10M8.5 8.5v5M11.5 8.5v5"/>'),
  eye: svg('<path d="M1.8 10S4.8 4.6 10 4.6 18.2 10 18.2 10 15.2 15.4 10 15.4 1.8 10 1.8 10z"/><circle cx="10" cy="10" r="2.6"/>'),
  "eye-off": svg('<path d="M3 3l14 14"/><path d="M8.2 4.9A8 8 0 0 1 10 4.6c5.2 0 8.2 5.4 8.2 5.4a14 14 0 0 1-2.4 3M5.4 6.4A14 14 0 0 0 1.8 10s3 5.4 8.2 5.4c1.4 0 2.6-.4 3.7-1"/><path d="M8.2 8.2a2.6 2.6 0 0 0 3.6 3.6"/>'),
  drive: svg('<rect x="2.6" y="10.4" width="14.8" height="5.4" rx="1.4"/><path d="M4.4 10.4L6.2 4.8c.2-.5.6-.8 1.1-.8h5.4c.5 0 .9.3 1.1.8l1.8 5.6"/><path d="M13.8 13.1h.01"/>'),
  eject: svg('<path d="M10 4.5L4.8 11h10.4z"/><path d="M4.8 14.6h10.4"/>'),
};

function applyIcons(root) {
  root.querySelectorAll("[data-icon]").forEach((b) => {
    b.innerHTML = ICONS[b.dataset.icon] || "";
    if (b.dataset.tip && !b.hasAttribute("aria-label")) b.setAttribute("aria-label", b.dataset.tip);
  });
}

// --------------------------------------------------------------- tooltips
// Hover any element with data-tip for a short description (shown after a
// brief delay, like macOS help tags).
let tipTimer;
function showTip(target) {
  const tip = $("#tip");
  const text = target.dataset.tip;
  if (!text) return;
  tip.textContent = text;
  tip.classList.remove("hidden");
  const r = target.getBoundingClientRect();
  const w = tip.offsetWidth, h = tip.offsetHeight;
  let x = r.left + r.width / 2 - w / 2;
  x = Math.max(8, Math.min(x, window.innerWidth - w - 8));
  let y = r.bottom + 8;
  if (y + h > window.innerHeight - 8) y = r.top - h - 8;
  tip.style.left = x + "px";
  tip.style.top = y + "px";
}
function hideTip() {
  clearTimeout(tipTimer);
  $("#tip").classList.add("hidden");
}
function initTips() {
  document.addEventListener("mouseover", (e) => {
    const t = e.target.closest("[data-tip]");
    if (!t) return;
    clearTimeout(tipTimer);
    tipTimer = setTimeout(() => showTip(t), 450);
  });
  document.addEventListener("mouseout", (e) => {
    const t = e.target.closest("[data-tip]");
    if (t && !t.contains(e.relatedTarget)) hideTip();
  });
  document.addEventListener("mousedown", hideTip, true);
  window.addEventListener("blur", hideTip);
}

// ------------------------------------------------------------ drag and drop
// Files dragged in from Finder arrive as Tauri window events (the webview's
// own HTML drop events don't carry file paths).
function listen(event, cb) {
  return invoke("plugin:event|listen", {
    event,
    target: { kind: "Any" },
    handler: T.transformCallback((msg) => cb(msg.payload)),
  });
}

// Folder row (or the list itself) under a window position.
function dropTarget(pos) {
  if (state.view !== "browser" || !pos) return null;
  const r = window.devicePixelRatio || 1;
  const el = document.elementFromPoint(pos.x / r, pos.y / r);
  if (!el || !el.closest(".file-table, .path-bar")) return null;
  const row = el.closest(".file-row[data-dir]");
  return { row, path: row ? row.dataset.path : state.browserPath };
}

function markDrop(t) {
  document.querySelectorAll(".drop-into").forEach((x) => x.classList.remove("drop-into"));
  $(".file-table").classList.toggle("drop-here", !!t && !t.row);
  if (t && t.row) t.row.classList.add("drop-into");
}

function initDragDrop() {
  const failed = (e) => console.error("drag and drop unavailable:", e);
  listen("tauri://drag-over", (p) => { if (!state.draggingOut) markDrop(dropTarget(p.position)); }).catch(failed);
  listen("tauri://drag-leave", () => markDrop(null)).catch(failed);
  listen("tauri://drag-drop", async (p) => {
    const t = dropTarget(p.position);
    markDrop(null);
    if (state.draggingOut || !t || !p.paths || !p.paths.length || !state.selectedConnId) return;
    const where = t.path === "/" ? "this folder" : '"' + t.path.split("/").pop() + '"';
    const what = p.paths.length === 1 ? '"' + p.paths[0].split("/").pop() + '"' : p.paths.length + " items";
    setStatus("Uploading " + what + "…");
    try {
      const n = await invoke("upload_paths", { id: state.selectedConnId, destDir: t.path, paths: p.paths });
      toast("Uploaded " + n + " file" + (n === 1 ? "" : "s") + " to " + where);
    } catch (e) {
      toast("Upload failed: " + e, 6000);
    }
    await browse(state.browserPath);
  }).catch(failed);
}

// Refresh mount state without touching the toolbar (sidebar badges only).
async function refreshMountsQuiet() {
  try {
    state.mounts = await invoke("list_mounted");
    state.mounted = new Set(state.mounts.map((m) => m.id));
    for (const err of await invoke("take_mount_errors")) toast("Could not mount " + err, 6000);
  } catch (e) {}
  renderSidebar();
  if (state.view === "browser") refreshMountState();
}

// ------------------------------------------------------------------- helpers
const $ = (sel) => document.querySelector(sel);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

let toastTimer;
function toast(msg, ms = 3200) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), ms);
}

// ------------------------------------------------------------------ dialogs
// Modal dialogs (#modal, #ask) keep keyboard focus inside while open: the
// rest of the app is made inert, Tab / Shift+Tab wrap around the dialog's
// controls, and closing returns focus to the element that opened it. `ask`
// can open on top of the preview modal, so open dialogs form a stack.
const dialogs = []; // [{ box, opener }]

function focusables(box) {
  return [...box.querySelectorAll('button, input, textarea, select, a[href], [tabindex]:not([tabindex="-1"])')]
    .filter((x) => !x.disabled && x.getClientRects().length > 0);
}

function openDialog(box, focusEl) {
  if (!dialogs.some((d) => d.box === box)) {
    const top = dialogs[dialogs.length - 1];
    if (top) top.box.inert = true;
    dialogs.push({ box, opener: document.activeElement });
    $("#app").inert = true;
  }
  box.classList.remove("hidden");
  const target = focusEl || focusables(box)[0];
  if (target) target.focus();
}

function closeDialog(box) {
  box.classList.add("hidden");
  const i = dialogs.findIndex((d) => d.box === box);
  if (i < 0) return;
  const [{ opener }] = dialogs.splice(i, 1);
  const top = dialogs[dialogs.length - 1];
  if (top) top.box.inert = false;
  else $("#app").inert = false;
  // The opener may have been re-rendered meanwhile (a file row, say).
  const back = opener && opener.isConnected && opener !== document.body ? opener
    : (top ? focusables(top.box)[0] : $(".file-row.selected"));
  if (back) back.focus();
}

function initDialogs() {
  document.addEventListener("keydown", (e) => {
    const top = dialogs[dialogs.length - 1];
    if (!top || e.key !== "Tab") return;
    const items = focusables(top.box);
    if (!items.length) { e.preventDefault(); return; }
    const first = items[0], last = items[items.length - 1];
    const inside = top.box.contains(document.activeElement);
    if (e.shiftKey && (document.activeElement === first || !inside)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && (document.activeElement === last || !inside)) { e.preventDefault(); first.focus(); }
  });
  // Belt and braces: anything that still pulls focus out goes back in.
  document.addEventListener("focusin", (e) => {
    const top = dialogs[dialogs.length - 1];
    if (top && !top.box.contains(e.target)) {
      const first = focusables(top.box)[0];
      if (first) first.focus();
    }
  });
}

// In-app replacement for window.prompt / window.confirm, which the Tauri
// webview on macOS silently ignores (prompt returns null, confirm false).
// Resolves to the entered text (prompt), true (confirm), or null if cancelled.
function ask(message, { input = false, value = "", okLabel = "OK" } = {}) {
  return new Promise((resolve) => {
    const box = $("#ask");
    const field = $("#ask-input");
    const ok = $("#ask-ok");
    const cancel = $("#ask-cancel");
    $("#ask-msg").textContent = message;
    ok.textContent = okLabel;
    field.classList.toggle("hidden", !input);
    field.value = value;
    openDialog(box, input ? field : ok);
    if (input) field.select();

    const done = (result) => {
      closeDialog(box);
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      box.removeEventListener("keydown", onKey);
      box.removeEventListener("click", onBackdrop);
      resolve(result);
    };
    const onOk = () => done(input ? field.value : true);
    const onCancel = () => done(null);
    const onKey = (e) => {
      // Enter on a focused button (Cancel included) clicks that button.
      if (e.key === "Enter" && e.target.tagName !== "BUTTON") { e.preventDefault(); onOk(); }
      else if (e.key === "Escape") { e.preventDefault(); onCancel(); }
    };
    const onBackdrop = (e) => { if (e.target === box) onCancel(); };
    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    box.addEventListener("keydown", onKey);
    box.addEventListener("click", onBackdrop);
  });
}

function fmtSize(n) {
  if (n == null) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

function fileIcon(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  const map = { pdf: "📕", txt: "📄", md: "📝", log: "📃", json: "🧾", csv: "📊", xls: "📊", xlsx: "📊", png: "🖼️", jpg: "🖼️", jpeg: "🖼️", gif: "🖼️", svg: "🖼️", zip: "🗜️", tar: "🗜️", gz: "🗜️", mp3: "🎵", wav: "🎵", mp4: "🎬", mov: "🎬" };
  return map[ext] || "📄";
}

function parentPath(p) {
  if (!p || p === "/") return "/";
  const t = p.replace(/\/+$/, "");
  const idx = t.lastIndexOf("/");
  return idx <= 0 ? "/" : t.slice(0, idx);
}

// Arrow-key movement in a list or grid of focusable items (one tab stop per
// list: only the current item has tabIndex 0). Returns the item to move to,
// or null when the key isn't a movement key. `cols` > 1 for a grid, where
// Left/Right step one item and Up/Down one row.
function moveKey(ev, items, current, cols = 1) {
  if (ev.metaKey || ev.ctrlKey || ev.altKey) return null;
  const i = items.indexOf(current);
  let to;
  switch (ev.key) {
    case "ArrowDown": to = i + cols; break;
    case "ArrowUp": to = i - cols; break;
    case "ArrowRight": if (cols > 1) to = i + 1; break;
    case "ArrowLeft": if (cols > 1) to = i - 1; break;
    case "Home": to = 0; break;
    case "End": to = items.length - 1; break;
  }
  if (to === undefined || !items.length) return null;
  ev.preventDefault();
  return items[Math.max(0, Math.min(items.length - 1, to))];
}

function setTabStop(items, active) {
  items.forEach((x) => { x.tabIndex = x === active ? 0 : -1; });
}

// ------------------------------------------------------------------- views
function showView(name) {
  state.view = name;
  ["grid", "form", "browser", "empty"].forEach((v) => {
    $("#view-" + v).classList.toggle("hidden", v !== name);
  });
  if (name === "browser") {
    const c = state.connections.find((c) => c.id === state.selectedConnId);
    setWindowTitle(c ? "CloudUp - " + c.name : "CloudUp");
  } else {
    setWindowTitle("Connections");
  }
}

// ------------------------------------------------------------------- sidebar
function renderSidebar() {
  const list = $("#conn-list");
  // Rebuilding the list drops focus; put it back on the selected item.
  const hadFocus = list.contains(document.activeElement);
  const focusedId = hadFocus ? document.activeElement.dataset.id : null;
  list.innerHTML = "";
  for (const c of state.connections) {
    const li = el("li", "conn-item" + (c.id === state.selectedConnId ? " selected" : ""));
    li.dataset.id = c.id;
    const icon = el("img", "ci-icon");
    icon.src = TYPES.find((t) => t.type === connTypeKey(c.type))?.icon || "icons/s3.png";
    const stack = el("div", "ci-stack");
    stack.appendChild(el("span", "ci-name", c.name));
    if (c.bucket && c.bucket !== "/") stack.appendChild(el("span", "ci-sub", c.bucket));
    li.appendChild(icon);
    li.appendChild(stack);
    if (state.mounted.has(c.id)) {
      const badge = el("span", "ci-mounted");
      badge.innerHTML = ICONS.drive;
      badge.dataset.tip = "Mounted as a drive";
      li.appendChild(badge);
    }
    li.setAttribute("role", "button");
    li.addEventListener("click", () => selectConnection(c.id));
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectConnection(c.id); return; }
      const to = moveKey(e, [...list.children], li);
      if (to && to !== li) selectConnection(to.dataset.id);
    });
    list.appendChild(li);
  }
  const items = [...list.children];
  const current = items.find((x) => x.dataset.id === state.selectedConnId) ||
    items.find((x) => x.dataset.id === focusedId) || items[0];
  setTabStop(items, current);
  if (hadFocus && current) current.focus();
}

async function selectConnection(id) {
  state.selectedConnId = id;
  state.browserPath = "/";
  state.selectedEntry = null;
  state._lastEntries = null;
  renderSidebar();
  showView("browser");
  await browse("/");
  await refreshMountState();
}

// --------------------------------------------------------------------- grid
function renderGrid() {
  const grid = $("#type-grid");
  grid.innerHTML = "";
  for (const t of TYPES) {
    if (!isFunctional(t.type)) continue;
    const tile = el("div", "type-tile");
    tile.setAttribute("role", "button");
    const icon = el("img", "tt-icon");
    icon.src = t.icon;
    icon.alt = "";
    tile.appendChild(icon);
    tile.appendChild(el("span", "tt-label", t.label));
    tile.addEventListener("click", () => openForm(t.type, null));
    tile.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openForm(t.type, null); return; }
      const tiles = [...grid.children];
      const cols = getComputedStyle(grid).gridTemplateColumns.split(" ").length || 1;
      const to = moveKey(e, tiles, tile, cols);
      if (to) { setTabStop(tiles, to); to.focus(); }
    });
    grid.appendChild(tile);
  }
  setTabStop([...grid.children], grid.firstElementChild);
}

// If the backend's list couldn't be read, offer every type and let the
// backend report the error on use rather than showing an empty grid.
function isFunctional(type) {
  return state.functional.size === 0 || state.functional.has(SERDE[type]);
}

// --------------------------------------------------------------------- form
async function openForm(type, conn) {
  state.selectedType = type;
  state.editingId = conn ? conn.id : null;
  state.formIsNew = !conn;
  const meta = TYPES.find((t) => t.type === type);
  const connMeta = CONN[type] || {};
  const isOAuth = !!connMeta.oauth;

  $("#form-icon").innerHTML = "";
  const img = el("img");
  img.src = meta.icon;
  $("#form-icon").appendChild(img);
  $("#form-title").textContent = conn ? "Edit Connection" : meta.label;
  $("#form-sub").textContent = isOAuth
    ? (conn ? "Reconnect, or update these settings for the account."
             : "Paste your app credentials, then Connect to sign in via your browser.")
    : (conn ? "Update the settings for this connection."
             : "Enter your credentials to connect and mount.");

  const form = $("#conn-form");
  form.innerHTML = "";
  const fields = FORMS[type] || [];
  const defaultEndpoint = connMeta.endpoint || "";
  const defaultRegion = connMeta.region || "";

  for (const f of fields) {
    form.appendChild(el("label", "field-label", f.label));
    const input = document.createElement("input");
    input.type = f.type || "text";
    input.name = f.key;
    if (f.placeholder) input.placeholder = f.placeholder;

    if (f.key === "secret") {
      // For OAuth the keychain secret is the token (set by Connect) and is not
      // typed here; no OAuth form declares a `secret` field, so this branch is
      // only reached for the typed-password backends.
      input.value = "";
      input.dataset.loaded = "1";
      if (conn && !isOAuth) fillStored(input, () => invoke("get_secret", { id: conn.id }), null);
    } else if (f.key === "client_secret") {
      // Kept in the keychain; older configs still have it in `fields`.
      input.value = "";
      input.dataset.loaded = "1";
      if (conn) {
        const legacy = (conn.fields && conn.fields.client_secret) || null;
        fillStored(input, () => invoke("get_field_secret", { id: conn.id, key: "client_secret" }), legacy);
      }
    } else if (f.field) {
      input.value = conn ? (conn.fields ? conn.fields[f.key] || "" : "") : "";
    } else if (f.key === "name") {
      input.value = conn ? conn.name : "New Connection";
    } else if (f.key === "endpoint") {
      input.value = conn ? (conn.endpoint || "") : defaultEndpoint;
    } else if (f.key === "region") {
      input.value = conn ? (conn.region || "") : defaultRegion;
    } else if (f.key === "bucket") {
      input.value = conn ? (conn.bucket || "/") : "/";
    } else if (f.key === "access_key") {
      input.value = conn ? (conn.access_key || "") : "";
    } else {
      input.value = conn ? (conn[f.key] || "") : "";
    }

    if (f.key === "client_id") input.addEventListener("input", updateConnectEnabled);
    // Enter in any field submits, like a native form.
    input.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      if (isOAuth && !$("#btn-connect").disabled && $("#btn-mount").disabled) connectOAuth();
      else if (!$("#btn-mount").disabled) saveAndMount();
    });
    if (f.pick) {
      const row = el("div", "field-row");
      const pick = el("button", "btn ghost small", "Choose…");
      pick.type = "button";
      pick.dataset.tip = "Choose the file in Finder (in the dialog, press ⌘⇧. to show hidden folders like .ssh)";
      pick.addEventListener("click", () => pickFile(input));
      row.append(input, pick);
      form.appendChild(row);
    } else {
      form.appendChild(input);
    }
  }

  // Start-up option (all types).
  form.appendChild(el("span", "field-label", ""));
  const auto = el("label", "check-row");
  const box = document.createElement("input");
  box.type = "checkbox";
  box.name = "auto_mount";
  box.checked = !!(conn && conn.fields && conn.fields.auto_mount === "1");
  auto.append(box, el("span", null, "Mount as a drive automatically when I log in"));
  auto.dataset.tip = "CloudUp opens in the background at login and mounts this connection in Finder.";
  form.appendChild(auto);

  // Button states.
  $("#btn-mount").textContent = conn ? "Save" : "Mount";
  const works = isFunctional(type);
  $("#btn-mount").disabled = !works;
  $("#btn-test").disabled = !works;
  $("#btn-connect").classList.toggle("hidden", !isOAuth);
  $("#btn-test").classList.toggle("hidden", isOAuth); // Connect doubles as the test.

  if (isOAuth) await refreshOAuthState(conn ? conn.id : null);

  showView("form");
}

// Fill a secret field from the keychain without ever saving a stale or
// half-loaded value: until the stored value has loaded (or the user types),
// the field stays empty and `dataset.loaded` is "", and saving then keeps
// what is stored. The flag lives on this input, so a late reply for an
// earlier form can't touch a newer one. `fallback` is used when nothing is
// stored or the lookup fails (e.g. a value still in an older config).
function fillStored(input, load, fallback) {
  input.dataset.loaded = "";
  input.addEventListener("input", () => { input.dataset.loaded = "1"; });
  load()
    .then((v) => ({ ok: true, v }), () => ({ ok: false, v: null }))
    .then(({ ok, v }) => {
      if (input.dataset.loaded) return; // the user typed a new one
      const value = v != null ? v : fallback;
      if (value == null && !ok) return; // unknown: leave the stored value alone
      input.value = value || "";
      input.dataset.loaded = "1";
    });
}

// "Choose…" next to a path field: native file picker, result into the field.
async function pickFile(input) {
  try {
    const picked = await invoke("plugin:dialog|open", { options: { multiple: false, directory: false } });
    const p = Array.isArray(picked) ? picked[0] : picked;
    if (!p) return;
    input.value = p;
    input.focus();
  } catch (e) {
    toast("Could not open the file picker: " + e);
  }
}

async function refreshOAuthState(id) {
  if (!CONN[state.selectedType]?.oauth) return;
  if (id) state.editingId = id;
  const hasToken = !!(id && (await invoke("get_secret", { id }).catch(() => null)));
  $("#btn-connect").textContent = hasToken ? "Reconnect" : "Connect";
  $("#btn-mount").disabled = !hasToken;
  updateConnectEnabled();
}

// Disable Connect until a Client ID has been entered.
function updateConnectEnabled() {
  const cid = $("#conn-form").querySelector('[name="client_id"]');
  const btn = $("#btn-connect");
  if (!cid || !btn) return;
  btn.disabled = cid.value.trim() === "";
}

function collectForm() {
  const type = state.selectedType;
  const form = $("#conn-form");
  // A secret field whose stored value hasn't loaded yet reads as "" (the
  // backend then keeps what it has stored).
  const get = (k) => {
    const i = form.querySelector(`[name="${k}"]`);
    return i && i.dataset.loaded !== "" ? i.value.trim() : "";
  };
  const fields = FORMS[type] || [];

  const conn = {
    id: state.editingId || crypto.randomUUID(),
    name: get("name") || "New Connection",
    type: SERDE[type] || type,
    endpoint: get("endpoint"),
    region: get("region"),
    access_key: get("access_key"),
    bucket: normalizeBucket(get("bucket")),
    secret: get("secret"),
    fields: {},
  };
  for (const f of fields) {
    if (f.field) conn.fields[f.key] = get(f.key);
  }
  conn.fields.auto_mount = form.querySelector('[name="auto_mount"]')?.checked ? "1" : "";
  splitBucketHost(conn);
  return conn;
}

// The S3 backend uses path-style URLs (endpoint/bucket/key). Providers show a
// bucket-specific "origin" URL (https://<bucket>.sfo3.digitaloceanspaces.com,
// https://<bucket>.s3.<region>.amazonaws.com) that people paste as the
// endpoint; move the bucket out of the host so requests are addressed right.
function splitBucketHost(conn) {
  if (conn.type !== "s3" && conn.type !== "backblaze") return;
  const m = /^(https?:\/\/)([^./]+)\.((?:[a-z0-9-]+\.digitaloceanspaces\.com)|(?:s3[.-][a-z0-9.-]*amazonaws\.com))\/?$/i.exec(conn.endpoint);
  if (!m) return;
  const [, scheme, bucket, host] = m;
  conn.endpoint = scheme + host;
  if (conn.bucket === "/") conn.bucket = "/" + bucket;
}

// Normalize a bucket/path to an absolute path with a single leading slash.
function normalizeBucket(raw) {
  const s = (raw || "").trim();
  if (!s || s === "/") return "/";
  return "/" + s.replace(/^\/+/, "").replace(/\/+$/, "");
}

// Open the form pre-filled with a saved connection's settings.
function editConnection(id) {
  const c = state.connections.find((x) => x.id === id);
  if (!c) { toast("Select a connection to edit."); return; }
  openForm(connTypeKey(c.type), c);
}

async function saveAndMount() {
  const btn = $("#btn-mount");
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    await saveAndMountInner();
  } finally {
    btn.disabled = false;
  }
}

async function saveAndMountInner() {
  const conn = collectForm();
  // Pin the id so a second click can't create a duplicate connection.
  state.editingId = conn.id;
  const isOAuth = !!CONN[state.selectedType]?.oauth;
  // An OAuth connection is already saved by Connect, but its form still
  // means "add": Mount then mounts it.
  const isEdit = !state.formIsNew;
  try {
    if (isEdit) {
      // Editing: just save. Don't auto-mount; a mounted drive keeps the old
      // settings until it is unmounted and mounted again.
      const field = $("#conn-form").querySelector('[name="secret"]');
      const loaded = !field || field.dataset.loaded === "1";
      const secret = isOAuth || !loaded ? null : (conn.secret || "");
      await invoke("save_connection", { conn: stripSecret(conn), secret });
      state.connections = await invoke("list_connections");
      await syncLoginItem();
      toast(state.mounted.has(conn.id)
        ? "Saved. Unmount and mount again to apply the changes to the drive."
        : "Saved.");
      await selectConnection(conn.id);
      return;
    }

    // OAuth tokens are stored by `connect_oauth`; pass `secret: null` so we
    // don't clobber the token with the (empty) form value.
    const secret = isOAuth ? null : (conn.secret || "");
    await invoke("save_connection", { conn: stripSecret(conn), secret });
    state.connections = await invoke("list_connections");
    await syncLoginItem();
    renderSidebar();
    if (isOAuth) await refreshOAuthState(conn.id);

    // Attempt to mount as a drive.
    state.mountAvailable = await invoke("mount_available");
    state.mountNote = await invoke("mount_availability_note");
    if (state.mountAvailable) {
      try {
        const info = await invoke("mount_connection", { id: conn.id });
        toast("Saved and mounted in Finder at " + info.mount_point);
      } catch (e) {
        toast("Saved. Drive mount failed: " + e, 6000);
      }
    } else {
      toast("Saved. " + (state.mountNote || ""));
    }

    await selectConnection(conn.id);
  } catch (e) {
    toast("Error: " + e);
  }
}

// CloudUp opens at login exactly when some connection should mount then.
async function syncLoginItem() {
  const want = state.connections.some((c) => c.fields && c.fields.auto_mount === "1");
  try {
    const have = await invoke("get_launch_at_login");
    if (have !== want) await invoke("set_launch_at_login", { enabled: want });
  } catch (e) {
    toast("Could not update the login item: " + e, 6000);
  }
}

function stripSecret(conn) {
  const c = { ...conn };
  delete c.secret;
  return c;
}

// OAuth provider: run the PKCE browser flow, then refresh the saved list.
async function connectOAuth() {
  const type = state.selectedType;
  const conn = collectForm();
  if (!CONN[type]?.oauth) return;
  if ((conn.fields.client_id || "").trim() === "") {
    toast("Enter a Client ID before connecting.");
    return;
  }
  try {
    $("#btn-connect").disabled = true;
    const label = (TYPES.find((t) => t.type === type) || {}).label || "your provider";
    toast("Opening browser to sign in with " + label + "…");
    const msg = await invoke("connect_oauth", { conn });
    toast(msg);
    state.connections = await invoke("list_connections");
    renderSidebar();
    await refreshOAuthState(conn.id);
  } catch (e) {
    toast("Connect failed: " + e);
  } finally {
    $("#btn-connect").disabled = false;
  }
}

async function testConnection() {
  const conn = collectForm();
  try {
    $("#btn-test").disabled = true;
    const n = await invoke("test_connection", { conn: stripSecret(conn), secret: conn.secret || "" });
    toast("Connection OK — " + n + " item(s) at root.");
  } catch (e) {
    toast("Connection failed: " + e);
  } finally {
    $("#btn-test").disabled = false;
  }
}

// ------------------------------------------------------------------ browser
async function browse(path) {
  const id = state.selectedConnId;
  if (!id) return;
  const seq = ++state.browseSeq;
  state.browserPath = path;
  state.selectedEntry = null;
  state._lastEntries = null;
  renderCrumbs();
  const listEl = $("#file-list");
  // Opening a folder (or deleting) from the keyboard keeps focus in the list.
  const keepFocus = listEl.contains(document.activeElement);
  listEl.innerHTML = "";
  setStatus("Loading…");
  try {
    const entries = await invoke("browse", { id, path });
    if (seq !== state.browseSeq) return; // another folder or connection was opened meanwhile
    state._lastEntries = entries;
    renderFileList(entries);
    const first = listEl.querySelector(".file-row[tabindex='0']");
    if (keepFocus && first && (document.activeElement === document.body || !document.activeElement)) first.focus();
  } catch (e) {
    if (seq !== state.browseSeq) return;
    listEl.innerHTML = "";
    const row = el("div", "file-row empty");
    row.appendChild(el("span", "fr-name", "⚠️  Could not load: " + e));
    listEl.appendChild(row);
    setStatus("Error");
  }
}

// Path bar: connection name, then the full server path of the current folder.
// The connection's base folder is the browser's "/" root; folders above it
// are shown for context but are not links.
function renderCrumbs() {
  const c = $("#crumbs");
  c.innerHTML = "";
  const conn = state.connections.find((x) => x.id === state.selectedConnId);
  $("#browser-title").textContent = conn ? conn.name : "";

  const add = (label, path) => {
    if (c.children.length) c.appendChild(el("span", "crumb-sep", "›"));
    const cr = el("span", "crumb", label);
    if (path == null) cr.classList.add("label");
    else if (path === state.browserPath) cr.classList.add("current");
    else cr.addEventListener("click", () => browse(path));
    c.appendChild(cr);
  };

  const base = conn ? (conn.bucket || "/").split("/").filter(Boolean) : [];
  const rel = state.browserPath.split("/").filter(Boolean);
  add(conn ? conn.name : "Root", base.length ? null : "/");
  base.forEach((seg, i) => add(seg, i === base.length - 1 ? "/" : null));
  let acc = "";
  for (const seg of rel) { acc += "/" + seg; add(seg, acc); }
  c.title = "/" + base.concat(rel).join("/");
}

// Finder-style folder glyph (blue, like macOS).
const FOLDER_SVG = '<svg viewBox="0 0 20 16" aria-hidden="true"><path d="M1.5 3.2c0-.9.7-1.7 1.7-1.7h4.1c.5 0 .9.2 1.2.5l1.1 1.1h7.2c.9 0 1.7.8 1.7 1.7v8.9c0 .9-.8 1.7-1.7 1.7H3.2c-1 0-1.7-.8-1.7-1.7V3.2z" fill="#3a8ee8"/><path d="M1.5 5.6h17v7.9c0 .9-.8 1.7-1.7 1.7H3.2c-1 0-1.7-.8-1.7-1.7V5.6z" fill="#5fb0f7"/></svg>';

// "Today at 5:14 PM" / "Jan 30, 2025 at 7:24 PM", like Finder. Falls back
// to the server's own text (e.g. FTP's "Oct 13 18:52") when it isn't a date.
function fmtDate(raw) {
  if (!raw) return "--";
  const d = new Date(raw);
  if (isNaN(d)) return raw;
  const time = d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  const today = new Date();
  const yest = new Date(today); yest.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return "Today at " + time;
  if (d.toDateString() === yest.toDateString()) return "Yesterday at " + time;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) + " at " + time;
}

const KINDS = { pdf: "PDF document", txt: "Plain text", md: "Markdown", log: "Log file", json: "JSON", csv: "CSV document",
  xls: "Excel workbook", xlsx: "Excel workbook", doc: "Word document", docx: "Word document", png: "PNG image", jpg: "JPEG image",
  jpeg: "JPEG image", gif: "GIF image", svg: "SVG image", webp: "WebP image", zip: "ZIP archive", tar: "Tar archive", gz: "Gzip archive",
  mp3: "MP3 audio", wav: "WAV audio", mp4: "MPEG-4 movie", mov: "QuickTime movie", html: "HTML text", htm: "HTML text", php: "PHP script",
  js: "JavaScript", css: "CSS", py: "Python script", sh: "Shell script", sql: "SQL", xml: "XML", yml: "YAML", yaml: "YAML" };
function kindOf(e) {
  if (e.is_dir) return "Folder";
  const dot = e.name.lastIndexOf(".");
  if (dot <= 0) return "Document";
  const ext = e.name.slice(dot + 1).toLowerCase();
  return KINDS[ext] || ext.toUpperCase() + " file";
}

const isHiddenName = (name) => name.startsWith(".");

function renderFileList(all) {
  if (!all) return; // still loading, or the folder failed to load
  const listEl = $("#file-list");
  listEl.innerHTML = "";
  const entries = state.showHidden ? all : all.filter((e) => !isHiddenName(e.name));
  if (entries.length === 0) {
    const row = el("div", "file-row empty");
    row.appendChild(el("span", "fr-name", "This folder is empty."));
    listEl.appendChild(row);
  }
  $(".file-table").classList.toggle("with-perms", entries.some((e) => e.perms));
  const rows = () => [...listEl.querySelectorAll(".file-row[data-path]")];
  for (const e of entries) {
    const row = el("div", "file-row" + (state.selectedEntry && state.selectedEntry.path === e.path ? " selected" : ""));
    const name = el("span", "fr-name");
    const icon = el("span", "fr-icon");
    if (e.is_dir) icon.innerHTML = FOLDER_SVG; else icon.textContent = fileIcon(e.name);
    name.appendChild(icon);
    name.appendChild(el("span", null, e.name));
    row.appendChild(name);
    row.appendChild(el("span", "fr-date", fmtDate(e.modified)));
    row.appendChild(el("span", "fr-size", e.is_dir ? "--" : fmtSize(e.size)));
    row.appendChild(el("span", "fr-kind", kindOf(e)));
    row.appendChild(el("span", "fr-perms", e.perms || ""));

    // Toggle the highlight in place: rebuilding the list here would replace the
    // row between the two clicks of a double-click, so dblclick never fired.
    const select = () => {
      state.selectedEntry = e;
      listEl.querySelectorAll(".file-row.selected").forEach((r) => r.classList.remove("selected"));
      row.classList.add("selected");
      setTabStop(rows(), row);
    };
    row.addEventListener("click", select);
    row.addEventListener("focus", select);
    row.addEventListener("dblclick", () => openEntry(e));
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); openEntry(e); return; }
      if (ev.key === "Delete" || (ev.key === "Backspace" && ev.metaKey)) { ev.preventDefault(); deleteSelected(); return; }
      const to = moveKey(ev, rows(), row);
      if (to) { to.focus(); to.scrollIntoView({ block: "nearest" }); } // focus selects it
    });
    // Drag out to Finder: hand the gesture to a native file-promise drag.
    row.draggable = true;
    row.dataset.path = e.path;
    if (e.is_dir) row.dataset.dir = "1";
    row.addEventListener("dragstart", (ev) => {
      ev.preventDefault();
      state.selectedEntry = e;
      listEl.querySelectorAll(".file-row.selected").forEach((r) => r.classList.remove("selected"));
      row.classList.add("selected");
      state.draggingOut = true;
      invoke("drag_out", { id: state.selectedConnId, items: [{ name: e.name, path: e.path, is_dir: e.is_dir }] })
        .catch((err) => toast("Could not start the drag: " + err))
        .finally(() => setTimeout(() => (state.draggingOut = false), 400));
    });
    listEl.appendChild(row);
  }
  const rowEls = rows();
  setTabStop(rowEls, rowEls.find((r) => r.classList.contains("selected")) || rowEls[0]);

  const dirs = entries.filter((e) => e.is_dir).length;
  const hidden = all.length - entries.length;
  setStatus(entries.length + " item" + (entries.length === 1 ? "" : "s") +
    " (" + dirs + " folder" + (dirs === 1 ? "" : "s") + ")" +
    (hidden ? " · " + hidden + " hidden" : ""));
}

async function openEntry(e) {
  if (e.is_dir) {
    await browse(e.path);
  } else {
    await previewFile(e);
  }
}

// ------------------------------------------------------- file preview / editor
const PREVIEW_MAX = 1024 * 1024;   // 1 MiB — bigger files aren't shown inline
const EDIT_MAX = 10 * 1024 * 1024; // 10 MiB — bigger files can't open in the editor

let previewSeq = 0;
async function previewFile(e) {
  const seq = ++previewSeq;
  const path = e.path;
  state.previewEntry = e;
  $("#modal-title").textContent = e.name;
  const size = (e.is_dir || e.size == null) ? null : e.size;
  $("#modal-size").textContent = (e.is_dir || size == null) ? "" : "  ·  " + fmtSize(size);

  const body = $("#modal-body");
  const editor = $("#modal-editor");
  const editBtn = $("#modal-edit");

  // Reset to preview mode.
  setEdit(false);
  editor.value = "";
  editor.dataset.path = path;
  state._fileText = null;
  editBtn.classList.add("hidden");
  editBtn.textContent = "Edit";

  // Choose how much to read, driven by the listing's reported size.
  let cap;
  if (e.is_dir || size == null) cap = EDIT_MAX;        // unknown size: try the editor cap
  else if (size > EDIT_MAX) cap = 0;                   // too big for both — skip the read
  else if (size > PREVIEW_MAX) cap = EDIT_MAX;         // editable but not previewable
  else cap = PREVIEW_MAX;                              // previewable (and therefore editable)

  openDialog($("#modal"));
  body.classList.remove("hidden");
  body.textContent = "Loading…";

  if (cap === 0) {
    body.textContent = "This file is " + fmtSize(size) + " — too large to preview or edit. Use Download.";
    return;
  }

  try {
    const b64 = await invoke("read_file", { id: state.selectedConnId, path, maxBytes: cap });
    if (seq !== previewSeq) return; // another file was opened meanwhile
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const actual = bytes.length;
    // Only offer the editor for valid UTF-8 without NULs: saving re-encodes
    // the text, which would corrupt anything else.
    let text = null;
    if (bytes.every((b) => b !== 0)) {
      try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch (err) {}
    }

    if (text != null) {
      state._fileText = text;
      const tooBigToPreview = actual > PREVIEW_MAX;
      body.textContent = tooBigToPreview
        ? "This file is " + fmtSize(actual) + " — too large to preview, but you can edit or download it."
        : text;
      if (actual <= EDIT_MAX) editBtn.classList.remove("hidden");
    } else {
      body.textContent = "[Binary file — " + fmtSize(actual) + "]";
    }
  } catch (err) {
    if (seq === previewSeq) body.textContent = "Could not read file: " + err;
  }
}

function editorDirty() {
  return !$("#modal-editor").classList.contains("hidden") && state._fileText != null &&
    $("#modal-editor").value !== state._fileText;
}

async function closeModal() {
  if (editorDirty() && !(await ask("Discard your unsaved changes?", { okLabel: "Discard" }))) return;
  setEdit(false);
  closeDialog($("#modal"));
  previewSeq++;
  state.previewEntry = null;
}

// Toggle between the read-only preview and the text editor.
function setEdit(on) {
  const body = $("#modal-body");
  const editor = $("#modal-editor");
  const editBtn = $("#modal-edit");
  const saveBtn = $("#modal-save");
  if (on) {
    editor.value = state._fileText == null ? "" : state._fileText;
    body.classList.add("hidden");
    editor.classList.remove("hidden");
    editBtn.textContent = "Close editor";
    saveBtn.classList.remove("hidden");
  } else {
    body.classList.remove("hidden");
    editor.classList.add("hidden");
    editBtn.textContent = "Edit";
    saveBtn.classList.add("hidden");
  }
}

async function saveEditedFile() {
  const editor = $("#modal-editor");
  const path = editor.dataset.path;
  if (!path) return;
  try {
    $("#modal-save").disabled = true;
    await invoke("write_text", { id: state.selectedConnId, path, content: editor.value });
    state._fileText = editor.value;
    setEdit(false);
    $("#modal-body").textContent = editor.value;
    toast("Saved.");
  } catch (err) {
    toast("Save failed: " + err);
  } finally {
    $("#modal-save").disabled = false;
  }
}

// -------------------------------------------------------------- browser actions
async function upload() {
  try {
    const picked = await invoke("plugin:dialog|open", { options: { multiple: false, directory: false } });
    const localPath = Array.isArray(picked) ? picked[0] : picked;
    if (!localPath) return;
    const name = localPath.split(/[\\/]/).pop();
    const dest = (state.browserPath === "/" ? "" : state.browserPath) + "/" + name;
    setStatus("Uploading " + name + "…");
    await invoke("upload", { id: state.selectedConnId, cloudPath: dest, localPath: localPath });
    toast("Uploaded " + name);
    await browse(state.browserPath);
  } catch (e) {
    toast("Upload failed: " + e);
  }
}

async function newFolder() {
  const raw = await ask("New folder name:", { input: true, value: "New Folder", okLabel: "Create" });
  const name = (raw || "").trim();
  if (!name) return;
  if (name.includes("/") || name === "." || name === "..") {
    toast("Folder names can't contain \"/\" or be \".\" / \"..\".");
    return;
  }
  try {
    const dest = (state.browserPath === "/" ? "" : state.browserPath) + "/" + name;
    await invoke("mkdir_entry", { id: state.selectedConnId, path: dest });
    toast("Created " + name);
    await browse(state.browserPath);
  } catch (e) {
    toast("Could not create folder: " + e);
  }
}

async function downloadSelected() {
  const e = state.selectedEntry;
  if (!e) { toast("Select a file first."); return; }
  if (e.is_dir) { toast("To download a folder, drag it to Finder."); return; }
  try {
    setStatus("Downloading " + e.name + "…");
    const p = await invoke("download", { id: state.selectedConnId, cloudPath: e.path });
    toast("Saved to " + p);
  } catch (err) {
    toast("Download failed: " + err);
  } finally {
    renderFileList(state._lastEntries);
  }
}

async function deleteSelected() {
  const e = state.selectedEntry;
  if (!e) { toast("Select a file or folder first."); return; }
  const conn = state.connections.find((c) => c.id === state.selectedConnId);
  const emptyOnly = e.is_dir && conn && (conn.type === "ftp" || conn.type === "sftp");
  const what = e.is_dir ? 'the folder "' + e.name + '" and everything in it' : '"' + e.name + '"';
  const msg = "Delete " + what + "? This can't be undone." +
    (emptyOnly ? " (FTP and SFTP servers only delete empty folders.)" : "");
  if (!(await ask(msg, { okLabel: "Delete" }))) return;
  try {
    await invoke("remove_entry", { id: state.selectedConnId, path: e.path, isDir: e.is_dir });
    toast("Deleted " + e.name);
    await browse(state.browserPath);
  } catch (err) {
    toast("Delete failed: " + err);
  }
}

function setStatus(msg) { $("#status-bar").textContent = msg; }

// ------------------------------------------------------------ drive control
// One control per connection. Not mounted: a "Mount" button. Mounted: a green
// pill that opens the drive in Finder, with an eject button to unmount.
async function refreshMountState() {
  const box = $("#drive");
  if (!box) return;
  try { state.mounts = await invoke("list_mounted"); } catch (e) { /* keep last known */ }
  state.mounted = new Set(state.mounts.map((m) => m.id));
  try {
    for (const err of await invoke("take_mount_errors")) toast("Could not mount " + err, 6000);
  } catch (e) {}

  const id = state.selectedConnId;
  const info = id ? state.mounts.find((m) => m.id === id) : null;
  box.innerHTML = "";
  if (info) {
    const open = el("button", "drive-open");
    open.innerHTML = ICONS.drive;
    open.appendChild(el("span", null, "Mounted"));
    open.dataset.tip = "Mounted in Finder at " + info.mount_point + " — click to open";
    open.addEventListener("click", () => invoke("open_path", { path: info.mount_point }).catch((e) => toast("" + e)));
    const eject = el("button", "drive-eject");
    eject.innerHTML = ICONS.eject;
    eject.dataset.tip = "Unmount (eject) the drive";
    eject.addEventListener("click", () => setMounted(false));
    box.className = "drive on";
    box.append(open, eject);
  } else {
    const btn = el("button", "drive-mount");
    btn.innerHTML = ICONS.drive;
    btn.appendChild(el("span", null, "Mount"));
    btn.disabled = !state.mountAvailable;
    btn.dataset.tip = state.mountAvailable
      ? "Mount this connection as a drive in Finder"
      : (state.mountNote || "Drive mounting is unavailable on this system.");
    btn.addEventListener("click", () => setMounted(true));
    box.className = "drive";
    box.append(btn);
  }
  renderSidebar();
}

async function setMounted(on) {
  const id = state.selectedConnId;
  if (!id) return;
  const box = $("#drive");
  box.classList.add("busy");
  box.querySelectorAll("button").forEach((b) => (b.disabled = true));
  try {
    if (on) {
      setStatus("Mounting…");
      const info = await invoke("mount_connection", { id });
      toast("Mounted in Finder at " + info.mount_point);
    } else {
      await invoke("unmount_connection", { id });
      toast("Drive unmounted.");
    }
  } catch (e) {
    toast((on ? "Mount failed: " : "Unmount failed: ") + e, 6000);
  }
  await refreshMountState();
  renderFileList(state._lastEntries);
}

// -------------------------------------------------------------------- wiring
async function init() {
  try { state.functional = new Set(await invoke("functional_types")); } catch (e) { console.error("functional_types:", e); }
  try { state.connections = await invoke("list_connections"); } catch (e) { state.connections = []; }
  try {
    state.mountAvailable = await invoke("mount_available");
    state.mountNote = await invoke("mount_availability_note");
  } catch (e) {}
  try { state.mounts = await invoke("list_mounted"); state.mounted = new Set(state.mounts.map((m) => m.id)); } catch (e) {}

  applyIcons(document);
  initTips();
  initDialogs();
  invoke("plugin:app|version").then((v) => { $("#app-version").textContent = "CloudUp " + v; }).catch(() => {});
  // Footer links open in the default browser (the webview doesn't navigate).
  for (const a of document.querySelectorAll("#powered, #privacy")) {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      invoke("open_path", { path: a.getAttribute("href") }).catch((err) => toast("Could not open the link: " + err));
    });
  }
  initDragDrop();
  renderGrid();
  renderSidebar();

  // Sidebar buttons.
  $("#btn-add").addEventListener("click", () => { state.selectedConnId = null; renderSidebar(); showView("grid"); });
  $("#btn-empty-add").addEventListener("click", () => { state.selectedConnId = null; renderSidebar(); showView("grid"); });
  $("#btn-remove").addEventListener("click", async () => {
    if (!state.selectedConnId) { toast("Select a connection to remove."); return; }
    const c = state.connections.find((x) => x.id === state.selectedConnId);
    const isOAuth = c && CONN[connTypeKey(c.type)]?.oauth;
    if (!(await ask('Remove "' + (c ? c.name : "connection") + '"? Its saved ' +
      (isOAuth ? "sign-in" : "password") + " is deleted too.", { okLabel: "Remove" }))) return;
    try {
      await invoke("delete_connection", { id: state.selectedConnId });
      state.connections = await invoke("list_connections");
      await syncLoginItem();
      state.selectedConnId = null;
      renderSidebar();
      showView(state.connections.length ? "empty" : "grid");
    } catch (e) { toast("Error: " + e); }
  });

  // Form buttons.
  $("#btn-mount").addEventListener("click", saveAndMount);
  $("#btn-test").addEventListener("click", testConnection);
  $("#btn-connect").addEventListener("click", connectOAuth);
  $("#btn-cancel").addEventListener("click", () => {
    // Cancelling an edit goes back to that connection's files.
    if (state.editingId && state.connections.some((c) => c.id === state.editingId)) selectConnection(state.editingId);
    else if (state.connections.length) showView("empty"); else showView("grid");
  });
  $("#btn-edit-conn").addEventListener("click", () => editConnection(state.selectedConnId));
  $("#conn-list").addEventListener("dblclick", () => editConnection(state.selectedConnId));

  // Browser toolbar.
  $("#nav-up").addEventListener("click", () => browse(parentPath(state.browserPath)));
  $("#btn-refresh").addEventListener("click", () => browse(state.browserPath));
  $("#btn-upload").addEventListener("click", upload);
  $("#btn-download").addEventListener("click", downloadSelected);
  $("#btn-newfolder").addEventListener("click", newFolder);
  const eye = $("#btn-hidden");
  const paintEye = () => {
    eye.innerHTML = ICONS[state.showHidden ? "eye" : "eye-off"];
    eye.setAttribute("aria-pressed", state.showHidden ? "true" : "false");
    eye.classList.toggle("active", state.showHidden);
    eye.dataset.tip = state.showHidden
      ? "Hidden files are shown — click to hide them"
      : "Hidden files are hidden — click to show them";
  };
  paintEye();
  eye.addEventListener("click", () => {
    state.showHidden = !state.showHidden;
    savePref("showHidden", state.showHidden ? "1" : "0");
    if (state.selectedEntry && !state.showHidden && isHiddenName(state.selectedEntry.name)) state.selectedEntry = null;
    paintEye();
    showTip(eye);
    renderFileList(state._lastEntries);
  });
  $("#btn-delete").addEventListener("click", deleteSelected);
  // Drives may be mounted at startup (or ejected in Finder) while we run.
  window.addEventListener("focus", () => { if (state.view === "browser") refreshMountState(); else refreshMountsQuiet(); });
  setTimeout(refreshMountsQuiet, 2500);
  setTimeout(refreshMountsQuiet, 8000);

  // Modal.
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
  $("#modal").addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); closeModal(); } });
  $("#modal-edit").addEventListener("click", () => {
    if (state._fileText == null) return;
    setEdit($("#modal-editor").classList.contains("hidden"));
  });
  $("#modal-save").addEventListener("click", saveEditedFile);
  $("#modal-download").addEventListener("click", async () => {
    const e = state.previewEntry;
    if (!e) return;
    try {
      const p = await invoke("download", { id: state.selectedConnId, cloudPath: e.path });
      toast("Saved to " + p);
    } catch (err) { toast("Download failed: " + err); }
  });
  $("#modal-open").addEventListener("click", async () => {
    const e = state.previewEntry;
    if (!e) return;
    try {
      const p = await invoke("download", { id: state.selectedConnId, cloudPath: e.path });
      await invoke("open_path", { path: p });
    } catch (err) { toast("Could not open: " + err); }
  });

  // Initial view.
  if (state.connections.length) showView("empty"); else showView("grid");

  checkUpdates();
}

// ---------------------------------------------------------------- updates
async function checkUpdates() {
  try {
    const v = await invoke("check_for_updates");
    if (!v) return;
    const bar = el("div", "update-bar");
    bar.id = "update-bar";
    const btn = el("button", "btn primary");
    btn.textContent = "Update to v" + v;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Downloading…";
      try {
        await invoke("install_update");
        toast("Update installed — restarting…");
      } catch (err) {
        btn.disabled = false;
        btn.textContent = "Update to v" + v;
        toast("Update failed: " + err);
      }
    });
    bar.appendChild(el("span", null, "A new version of CloudUp is available."));
    bar.appendChild(btn);
    document.getElementById("content").prepend(bar);
  } catch (e) { /* quiet */ }
}

document.addEventListener("DOMContentLoaded", () => {
  init().catch((e) => { console.error("init:", e); toast("CloudUp could not start: " + e, 8000); });
});
