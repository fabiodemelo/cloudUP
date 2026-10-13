/* CloudMounter — frontend logic */

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
// the SERDE map below. FTP and SFTP are separate tiles (SFTP is "coming soon").
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
  pcloud:    { endpoint: "https://my.pcloud.com" },
  dropbox:   { oauth: true },
  gdrive:    { oauth: true },
  onedrive:  { oauth: true },
  box:       { oauth: true },
};

// Field descriptors per type. Shape: { key, label, type?, placeholder?, field? }
//   - `field: true` -> the value goes into `conn.fields[key]` (provider extra).
//   - key `secret`  -> a pseudo-field -> the separate `secret` command arg.
//   - everything else maps to a top-level `Connection` field.
const FORMS = {
  s3: [
    { key: "name",       label: "Name" },
    { key: "access_key", label: "Access Key ID" },
    { key: "secret",     label: "Secret Access Key", type: "password" },
    { key: "endpoint",   label: "S3 endpoint", placeholder: "https://s3.amazonaws.com" },
    { key: "region",     label: "Region", placeholder: "us-east-1" },
    { key: "bucket",     label: "Bucket / path", placeholder: "/" },
  ],
  backblaze: [
    { key: "name",       label: "Name" },
    { key: "access_key", label: "Application Key ID" },
    { key: "secret",     label: "Application Key", type: "password" },
    { key: "endpoint",   label: "S3 endpoint", placeholder: "https://s3.us-west-0.backblazeb2.com" },
    { key: "region",     label: "Region", placeholder: "us-west-0" },
    { key: "bucket",     label: "Bucket", placeholder: "/" },
  ],
  webdav: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "WebDAV URL", placeholder: "https://example.com/remote" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Path", placeholder: "/" },
  ],
  openstack: [
    { key: "name",           label: "Name" },
    { key: "endpoint",       label: "Auth URL", placeholder: "https://auth.example.com/v3" },
    { key: "access_key",     label: "Username" },
    { key: "secret",         label: "Password", type: "password" },
    { key: "user_domain",    label: "User domain",  field: true, placeholder: "Default" },
    { key: "project_domain", label: "Project domain", field: true, placeholder: "Default" },
    { key: "project",        label: "Project / bucket", field: true, placeholder: "my-bucket" },
  ],
  ftp: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "Host", placeholder: "ftp.example.com" },
    { key: "port",       label: "Port", field: true, placeholder: "21" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Remote path", placeholder: "/" },
  ],
  sftp: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "Host", placeholder: "sftp.example.com" },
    { key: "port",       label: "Port", field: true, placeholder: "22" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "key",        label: "Private key (optional)", field: true },
    { key: "bucket",     label: "Remote path", placeholder: "/" },
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
    { key: "endpoint",   label: "pCloud host", placeholder: "https://my.pcloud.com" },
    { key: "access_key", label: "Username (email)" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Path", placeholder: "/" },
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
    { key: "bucket",        label: "Folder / file ID", placeholder: "/" },
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

// Fallback for any type without an explicit form (currently: Mega).
const DEFAULT_FORM = [
  { key: "name",       label: "Name" },
  { key: "endpoint",   label: "Address / URL" },
  { key: "access_key", label: "Username" },
  { key: "secret",     label: "Password", type: "password" },
];

// -------------------------------------------------------------------- state
const state = {
  connections: [],
  functional: new Set(),      // serde names from functional_types()
  view: "empty",              // grid | form | browser | empty
  selectedType: null,         // grid key while in the form
  editingId: null,            // connection id being edited (null = new)
  selectedConnId: null,       // connection shown in the browser / sidebar
  browserPath: "/",
  selectedEntry: null,        // { name, path, is_dir, size }
  mounts: [],                 // raw list_mounted() result
  mounted: new Set(),         // ids currently mounted as drives
  mountAvailable: false,
  mountNote: "",
  _lastEntries: null,
  _fileText: null,            // decoded text of the file open in the modal
};

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

function fmtSize(n) {
  if (n == null) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

function fileIcon(isDir, name) {
  if (isDir) return "📁";
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

// Human-friendly name, mirroring Rust `Connection::display_name`. That is a
// method and is NOT serialized, so `c.display_name` is undefined in JS — we
// rebuild it from `name` + `bucket` here.
function displayName(c) {
  const bucket = (c.bucket || "").replace(/\/+$/, "");
  if (!bucket || bucket === "/") return c.name;
  return c.name + " [" + bucket + "]";
}

// ------------------------------------------------------------------- views
function showView(name) {
  state.view = name;
  ["grid", "form", "browser", "empty"].forEach((v) => {
    $("#view-" + v).classList.toggle("hidden", v !== name);
  });
  if (name === "browser") {
    const c = state.connections.find((c) => c.id === state.selectedConnId);
    setWindowTitle(c ? "CloudMounter - " + displayName(c) : "CloudMounter");
  } else {
    setWindowTitle("Connections");
  }
}

// ------------------------------------------------------------------- sidebar
function renderSidebar() {
  const list = $("#conn-list");
  list.innerHTML = "";
  for (const c of state.connections) {
    const li = el("li", "conn-item" + (c.id === state.selectedConnId ? " selected" : ""));
    const icon = el("img", "ci-icon");
    icon.src = TYPES.find((t) => t.type === connTypeKey(c.type))?.icon || "icons/s3.png";
    const stack = el("div", "ci-stack");
    stack.appendChild(el("span", "ci-name", c.name));
    if (c.bucket && c.bucket !== "/") stack.appendChild(el("span", "ci-sub", c.bucket));
    li.appendChild(icon);
    li.appendChild(stack);
    li.addEventListener("click", () => selectConnection(c.id));
    list.appendChild(li);
  }
}

async function selectConnection(id) {
  state.selectedConnId = id;
  state.browserPath = "/";
  state.selectedEntry = null;
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
    const works = state.functional.has(SERDE[t.type]);
    const tile = el("div", "type-tile" + (works ? "" : " disabled"));
    const icon = el("img", "tt-icon");
    icon.src = t.icon;
    tile.appendChild(icon);
    tile.appendChild(el("span", "tt-label", t.label));
    if (!works) tile.appendChild(el("span", "tt-badge", "soon"));
    tile.addEventListener("click", () => { if (works) openForm(t.type, null); else toast(t.label + " is coming soon."); });
    grid.appendChild(tile);
  }
}

// --------------------------------------------------------------------- form
async function openForm(type, conn) {
  state.selectedType = type;
  state.editingId = conn ? conn.id : null;
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
  const fields = FORMS[type] || DEFAULT_FORM;
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
      if (conn && !isOAuth) {
        invoke("get_secret", { id: conn.id }).then((s) => { if (s != null) input.value = s; });
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
    form.appendChild(input);
  }

  // Button states.
  const works = state.functional.has(SERDE[type]);
  $("#btn-mount").disabled = !works;
  $("#btn-test").disabled = !works;
  $("#btn-connect").classList.toggle("hidden", !isOAuth);
  $("#btn-test").classList.toggle("hidden", isOAuth); // Connect doubles as the test.

  if (isOAuth) await refreshOAuthState(conn ? conn.id : null);

  showView("form");
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
  const get = (k) => { const i = form.querySelector(`[name="${k}"]`); return i ? i.value.trim() : ""; };
  const fields = FORMS[type] || DEFAULT_FORM;

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
  return conn;
}

// Normalize a bucket/path to an absolute path with a single leading slash.
function normalizeBucket(raw) {
  const s = (raw || "").trim();
  if (!s || s === "/") return "/";
  return "/" + s.replace(/^\/+/, "").replace(/\/+$/, "");
}

async function saveAndMount() {
  const conn = collectForm();
  const isOAuth = !!CONN[state.selectedType]?.oauth;
  try {
    // OAuth tokens are stored by `connect_oauth`; pass `secret: null` so we
    // don't clobber the token with the (empty) form value.
    const secret = isOAuth ? null : (conn.secret || "");
    await invoke("save_connection", { conn: stripSecret(conn), secret });
    state.connections = await invoke("list_connections");
    state.editingId = conn.id;
    renderSidebar();
    if (isOAuth) await refreshOAuthState(conn.id);

    // Attempt to mount as a drive.
    state.mountAvailable = await invoke("mount_available");
    state.mountNote = await invoke("mount_availability_note");
    if (state.mountAvailable) {
      try {
        const info = await invoke("mount_connection", { id: conn.id });
        toast("Mounted at " + info.mount_point);
      } catch (e) {
        toast("Saved. Drive mount failed: " + e);
      }
    } else {
      toast("Saved. (Drive mounting needs macFUSE/WinFsp — using built-in browser.)");
    }

    await selectConnection(conn.id);
  } catch (e) {
    toast("Error: " + e);
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
  if (!state.selectedConnId) return;
  state.browserPath = path;
  state.selectedEntry = null;
  renderCrumbs();
  const listEl = $("#file-list");
  listEl.innerHTML = "";
  setStatus("Loading…");
  try {
    const entries = await invoke("browse", { id: state.selectedConnId, path });
    state._lastEntries = entries;
    renderFileList(entries);
    const dirs = entries.filter((e) => e.is_dir).length;
    setStatus(entries.length + " item" + (entries.length === 1 ? "" : "s") + " (" + dirs + " folder" + (dirs === 1 ? "" : "s") + ")");
  } catch (e) {
    listEl.innerHTML = "";
    const row = el("div", "file-row");
    row.appendChild(el("span", "fr-icon", "⚠️"));
    row.appendChild(el("span", "fr-name", "Could not load: " + e));
    listEl.appendChild(row);
    setStatus("Error");
  }
}

function renderCrumbs() {
  const c = $("#crumbs");
  c.innerHTML = "";
  const conn = state.connections.find((x) => x.id === state.selectedConnId);
  const rootLabel = conn ? displayName(conn) : "Root";

  const addCrumb = (label, path) => {
    if (c.children.length) c.appendChild(el("span", "crumb-sep", "/"));
    const cr = el("span", "crumb", label);
    if (path !== state.browserPath) cr.addEventListener("click", () => browse(path));
    else cr.classList.add("current");
    c.appendChild(cr);
  };

  addCrumb(rootLabel, "/");
  const segs = state.browserPath.split("/").filter(Boolean);
  let acc = "";
  for (const s of segs) {
    acc += "/" + s;
    addCrumb(s, acc);
  }
}

function renderFileList(entries) {
  const listEl = $("#file-list");
  listEl.innerHTML = "";
  if (entries.length === 0) {
    const row = el("div", "file-row");
    row.appendChild(el("span", "fr-icon", "🗂️"));
    row.appendChild(el("span", "fr-name", "(empty)"));
    listEl.appendChild(row);
  }
  for (const e of entries) {
    const row = el("div", "file-row" + (state.selectedEntry && state.selectedEntry.path === e.path ? " selected" : ""));
    row.appendChild(el("span", "fr-icon", fileIcon(e.is_dir, e.name)));
    row.appendChild(el("span", "fr-name", e.name));
    row.appendChild(el("span", "fr-size", e.is_dir ? "" : fmtSize(e.size)));

    row.addEventListener("click", () => {
      state.selectedEntry = e;
      renderFileList(state._lastEntries || []);
    });
    row.addEventListener("dblclick", () => openEntry(e));
    listEl.appendChild(row);
  }
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

async function previewFile(e) {
  const path = e.path;
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

  $("#modal").classList.remove("hidden");
  body.classList.remove("hidden");
  body.textContent = "Loading…";

  if (cap === 0) {
    body.textContent = "This file is " + fmtSize(size) + " — too large to preview or edit. Use Download.";
    return;
  }

  try {
    const b64 = await invoke("read_file", { id: state.selectedConnId, path, max_bytes: cap });
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const isText = [...bytes.slice(0, 1024)].every((b) => b !== 0); // any NUL => binary
    const actual = bytes.length;

    if (isText) {
      const text = new TextDecoder().decode(bytes);
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
    body.textContent = "Could not read file: " + err;
  }
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
    if (!picked || !picked[0]) return;
    const localPath = picked[0];
    const name = localPath.split(/[\\/]/).pop();
    const dest = (state.browserPath === "/" ? "" : state.browserPath) + "/" + name;
    setStatus("Uploading " + name + "…");
    await invoke("upload", { id: state.selectedConnId, cloud_path: dest, local_path: localPath });
    toast("Uploaded " + name);
    await browse(state.browserPath);
  } catch (e) {
    toast("Upload failed: " + e);
  }
}

async function newFolder() {
  const name = prompt("New folder name:");
  if (!name) return;
  try {
    const dest = (state.browserPath === "/" ? "" : state.browserPath) + "/" + name;
    await invoke("mkdir_entry", { id: state.selectedConnId, path: dest });
    toast("Created " + name);
    await browse(state.browserPath);
  } catch (e) {
    toast("Could not create folder: " + e);
  }
}

async function deleteSelected() {
  const e = state.selectedEntry;
  if (!e) return;
  if (!confirm('Delete "' + e.name + '"?')) return;
  try {
    await invoke("remove_entry", { id: state.selectedConnId, path: e.path, is_dir: e.is_dir });
    toast("Deleted " + e.name);
    await browse(state.browserPath);
  } catch (err) {
    toast("Delete failed: " + err);
  }
}

function setStatus(msg) { $("#status-bar").textContent = msg; }

// ------------------------------------------------- mount indicator / unmount
async function refreshMountState() {
  const chip = $("#mount-state");
  const btn = $("#btn-mount-toggle");
  if (!chip || !btn) return;
  const id = state.selectedConnId;
  try { state.mounts = await invoke("list_mounted"); } catch (e) { /* keep last known */ }
  state.mounted = new Set(state.mounts.map((m) => m.id));

  const info = id ? state.mounts.find((m) => m.id === id) : null;
  if (info) {
    chip.textContent = "Mounted · " + info.mount_point;
    chip.className = "mount-chip on";
    chip.title = "Mounted at " + info.mount_point;
    btn.textContent = "Unmount";
    btn.classList.remove("hidden");
    btn.disabled = false;
  } else if (state.mountAvailable) {
    chip.textContent = "Not mounted";
    chip.className = "mount-chip";
    chip.title = "This connection is not mounted as a drive yet.";
    btn.textContent = "Mount";
    btn.classList.remove("hidden");
    btn.disabled = false;
  } else {
    chip.textContent = "Browser only";
    chip.className = "mount-chip off";
    chip.title = state.mountNote || "Drive mounting is unavailable on this system.";
    btn.classList.add("hidden");
    btn.disabled = true;
  }
}

async function toggleMount() {
  const id = state.selectedConnId;
  if (!id) return;
  if (state.mounted.has(id)) {
    try {
      await invoke("unmount_connection", { id });
      toast("Unmounted.");
    } catch (e) { toast("Unmount failed: " + e); }
  } else {
    if (!state.mountAvailable) { toast(state.mountNote || "Mounting is unavailable."); return; }
    try {
      const info = await invoke("mount_connection", { id });
      toast("Mounted at " + info.mount_point);
    } catch (e) { toast("Mount failed: " + e); }
  }
  await refreshMountState();
}

// -------------------------------------------------------------------- wiring
async function init() {
  try { state.functional = new Set(await invoke("functional_types")); } catch (e) {}
  try { state.connections = await invoke("list_connections"); } catch (e) { state.connections = []; }
  try {
    state.mountAvailable = await invoke("mount_available");
    state.mountNote = await invoke("mount_availability_note");
  } catch (e) {}
  try { state.mounts = await invoke("list_mounted"); state.mounted = new Set(state.mounts.map((m) => m.id)); } catch (e) {}

  renderGrid();
  renderSidebar();

  // Sidebar buttons.
  $("#btn-add").addEventListener("click", () => { state.selectedConnId = null; renderSidebar(); showView("grid"); });
  $("#btn-empty-add").addEventListener("click", () => { state.selectedConnId = null; renderSidebar(); showView("grid"); });
  $("#btn-remove").addEventListener("click", async () => {
    if (!state.selectedConnId) return;
    const c = state.connections.find((x) => x.id === state.selectedConnId);
    if (!confirm('Remove "' + (c ? c.name : "connection") + '"?')) return;
    try {
      await invoke("delete_connection", { id: state.selectedConnId });
      state.connections = await invoke("list_connections");
      state.selectedConnId = null;
      renderSidebar();
      showView(state.connections.length ? "empty" : "grid");
    } catch (e) { toast("Error: " + e); }
  });

  // Form buttons.
  $("#btn-mount").addEventListener("click", saveAndMount);
  $("#conn-form").addEventListener("submit", (e) => {
    e.preventDefault();
    if (CONN[state.selectedType]?.oauth) connectOAuth(); else saveAndMount();
  });
  $("#btn-test").addEventListener("click", testConnection);
  $("#btn-connect").addEventListener("click", connectOAuth);
  $("#btn-cancel").addEventListener("click", () => {
    if (state.connections.length) showView("empty"); else showView("grid");
  });

  // Browser toolbar.
  $("#nav-up").addEventListener("click", () => browse(parentPath(state.browserPath)));
  $("#btn-refresh").addEventListener("click", () => browse(state.browserPath));
  $("#btn-upload").addEventListener("click", upload);
  $("#btn-newfolder").addEventListener("click", newFolder);
  $("#btn-delete").addEventListener("click", deleteSelected);
  const mbtn = $("#btn-mount-toggle");
  if (mbtn) mbtn.addEventListener("click", toggleMount);

  // Modal.
  $("#modal-close").addEventListener("click", () => $("#modal").classList.add("hidden"));
  $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("#modal").classList.add("hidden"); });
  $("#modal-edit").addEventListener("click", () => {
    if (state._fileText == null) return;
    setEdit($("#modal-editor").classList.contains("hidden"));
  });
  $("#modal-save").addEventListener("click", saveEditedFile);
  $("#modal-download").addEventListener("click", async () => {
    const e = state.selectedEntry;
    if (!e) return;
    try {
      const p = await invoke("download", { id: state.selectedConnId, cloud_path: e.path });
      toast("Saved to " + p);
    } catch (err) { toast("Download failed: " + err); }
  });
  $("#modal-open").addEventListener("click", async () => {
    const e = state.selectedEntry;
    if (!e) return;
    try {
      const p = await invoke("download", { id: state.selectedConnId, cloud_path: e.path });
      await invoke("open_path", { path: p });
    } catch (err) { toast("Could not open: " + err); }
  });

  // Initial view.
  if (state.connections.length) showView("empty"); else showView("grid");
}

document.addEventListener("DOMContentLoaded", init);
