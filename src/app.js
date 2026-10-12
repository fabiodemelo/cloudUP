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
const TYPES = [
  { type: "ftp",       label: "FTP & SFTP",      icon: "icons/ftp.png" },
  { type: "s3",        label: "Amazon S3",       icon: "icons/s3.png" },
  { type: "backblaze", label: "Backblaze",       icon: "icons/backblaze.png" },
  { type: "openstack", label: "OpenStack Swift", icon: "icons/openstack.png" },
  { type: "dropbox",   label: "Dropbox",         icon: "icons/dropbox.png" },
  { type: "gdrive",    label: "Google Drive",    icon: "icons/gdrive.png" },
  { type: "onedrive",  label: "OneDrive",        icon: "icons/onedrive.png" },
  { type: "box",       label: "Box",             icon: "icons/box.png" },
  { type: "mega",      label: "Mega",            icon: "icons/mega.png" },
  { type: "webdav",    label: "WebDAV",          icon: "icons/webdav.png" },
  { type: "pcloud",    label: "pCloud",          icon: "icons/pcloud.png" },
];

const FORMS = {
  s3: [
    { key: "name",       label: "Name" },
    { key: "access_key", label: "Access Key" },
    { key: "secret",     label: "Secret Key", type: "password" },
    { key: "endpoint",   label: "Server endpoint", placeholder: "https://s3.amazonaws.com" },
    { key: "region",     label: "Region", placeholder: "us-east-1" },
    { key: "bucket",     label: "Bucket", placeholder: "/" },
  ],
  webdav: [
    { key: "name",       label: "Name" },
    { key: "endpoint",   label: "URL", placeholder: "https://example.com/remote" },
    { key: "access_key", label: "Username" },
    { key: "secret",     label: "Password", type: "password" },
    { key: "bucket",     label: "Path", placeholder: "/" },
  ],
};

const DEFAULT_FORM = [
  { key: "name",       label: "Name" },
  { key: "endpoint",   label: "Address / URL" },
  { key: "access_key", label: "Username" },
  { key: "secret",     label: "Password", type: "password" },
];

// Map a saved connection's ctype (serde name) to our grid type key.
function connTypeKey(ctype) {
  const map = { s3: "s3", webdav: "webdav", dropbox: "dropbox", onedrive: "onedrive", googledrive: "gdrive", box: "box", mega: "mega", backblaze: "backblaze", openstack: "openstack", ftp: "ftp", sftp: "ftp", pcloud: "pcloud" };
  return map[ctype] || ctype;
}

// -------------------------------------------------------------------- state
const state = {
  connections: [],
  functional: new Set(["s3", "webdav"]),
  view: "empty",          // grid | form | browser | empty
  selectedType: null,     // type key while in the form
  editingId: null,        // connection id being edited (null = new)
  selectedConnId: null,   // connection shown in the browser / sidebar
  browserPath: "/",
  selectedEntry: null,    // { name, path, is_dir }
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

// ------------------------------------------------------------------- views
function showView(name) {
  state.view = name;
  ["grid", "form", "browser", "empty"].forEach((v) => {
    $("#view-" + v).classList.toggle("hidden", v !== name);
  });
  if (name === "browser") {
    const c = state.connections.find((c) => c.id === state.selectedConnId);
    setWindowTitle(c ? "CloudMounter - " + c.display_name : "CloudMounter");
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
}

// --------------------------------------------------------------------- grid
function renderGrid() {
  const grid = $("#type-grid");
  grid.innerHTML = "";
  for (const t of TYPES) {
    const works = state.functional.has(t.type);
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
function openForm(type, conn) {
  state.selectedType = type;
  state.editingId = conn ? conn.id : null;
  const meta = TYPES.find((t) => t.type === type);

  $("#form-icon").innerHTML = "";
  const img = el("img");
  img.src = meta.icon;
  $("#form-icon").appendChild(img);
  $("#form-title").textContent = conn ? "Edit Connection" : meta.label;
  $("#form-sub").textContent = conn ? "Update the settings for this connection." : "Enter your credentials to connect and mount.";

  const form = $("#conn-form");
  form.innerHTML = "";
  const fields = FORMS[type] || DEFAULT_FORM;

  // Pre-fill from existing connection (or defaults).
  const values = {
    name: conn ? conn.name : "New Connection",
    access_key: conn ? conn.access_key || "" : "",
    endpoint: conn ? conn.endpoint || "" : (meta && type === "s3" ? "https://s3.amazonaws.com" : ""),
    region: conn ? conn.region || "" : (type === "s3" ? "us-east-1" : ""),
    bucket: conn ? conn.bucket || "/" : "/",
  };

  for (const f of fields) {
    form.appendChild(el("label", "field-label", f.label));
    const input = document.createElement("input");
    input.type = f.type || "text";
    input.name = f.key;
    if (f.placeholder) input.placeholder = f.placeholder;
    let val = values[f.key];
    if (f.key === "secret") {
      // fetch the stored secret for editing
      val = "";
      if (conn) {
        invoke("get_secret", { id: conn.id }).then((s) => { if (s != null) input.value = s; });
      }
    } else if (val != null) {
      input.value = val;
    }
    form.appendChild(input);
  }

  // Enable/disable mount for non-functional types.
  const works = state.functional.has(type);
  $("#btn-mount").disabled = !works;
  $("#btn-test").disabled = !works;

  showView("form");
}

function collectForm() {
  const type = state.selectedType;
  const form = $("#conn-form");
  const get = (k) => { const i = form.querySelector(`[name="${k}"]`); return i ? i.value.trim() : ""; };
  const conn = {
    id: state.editingId || crypto.randomUUID(),
    name: get("name") || "New Connection",
    type,
    endpoint: get("endpoint"),
    region: get("region") || (type === "s3" ? "us-east-1" : ""),
    access_key: get("access_key"),
    bucket: (get("bucket") || "/").replace(/^\/+/, "") ? ("/" + get("bucket").trim().replace(/^\/+/, "").replace(/\/+$/, "")) : "/",
    secret: get("secret"),
  };
  // normalize bucket to always start with "/"
  if (conn.bucket !== "/") conn.bucket = "/" + conn.bucket;
  return conn;
}

async function saveAndMount() {
  const conn = collectForm();
  try {
    await invoke("save_connection", { conn: stripSecret(conn), secret: conn.secret || "" });
    state.connections = await invoke("list_connections");
    renderSidebar();

    // Attempt to mount as a drive.
    const available = await invoke("mount_available");
    if (available) {
      try {
        const info = await invoke("mount_connection", { id: conn.id });
        toast(`Mounted at ${info.mount_point}`);
      } catch (e) {
        toast("Saved. Drive mount failed: " + e);
      }
    } else {
      toast("Saved. (Drive mounting needs macFUSE/WinFsp — using built-in browser.)");
    }

    // Open the built-in browser for it.
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

async function testConnection() {
  const conn = collectForm();
  try {
    $("#btn-test").disabled = true;
    const n = await invoke("test_connection", { conn: stripSecret(conn), secret: conn.secret || "" });
    toast(`Connection OK — ${n} item(s) at root.`);
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
    setStatus(`${entries.length} item${entries.length === 1 ? "" : "s"} (${dirs} folder${dirs === 1 ? "" : "s"})`);
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
  const rootLabel = conn ? conn.display_name : "Root";

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
    const size = el("span", "fr-size", e.is_dir ? "" : fmtSize(e.size));
    row.appendChild(size);

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
    // Preview / download a file.
    await previewFile(e);
  }
}

async function previewFile(e) {
  $("#modal-title").textContent = e.name;
  const body = $("#modal-body");
  body.textContent = "Loading…";
  $("#modal").classList.remove("hidden");
  try {
    const b64 = await invoke("read_file", { id: state.selectedConnId, path: e.path });
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    // Heuristic: text vs binary.
    const sample = bytes.slice(0, 512);
    let isText = true;
    for (const b of sample) if (b === 0) { isText = false; break; }
    if (isText) body.textContent = new TextDecoder().decode(bytes);
    else body.textContent = `[Binary file — ${fmtSize(e.size)}]`;
  } catch (err) {
    body.textContent = "Could not read file: " + err;
  }
}

// --------------------------------------------------------------- browser actions
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
  if (!confirm(`Delete "${e.name}"?`)) return;
  try {
    await invoke("remove_entry", { id: state.selectedConnId, path: e.path, is_dir: e.is_dir });
    toast("Deleted " + e.name);
    await browse(state.browserPath);
  } catch (err) {
    toast("Delete failed: " + err);
  }
}

function setStatus(msg) { $("#status-bar").textContent = msg; }

// -------------------------------------------------------------------- wiring
async function init() {
  try { state.functional = new Set(await invoke("functional_types")); } catch (e) {}
  try { state.connections = await invoke("list_connections"); } catch (e) { state.connections = []; }

  renderGrid();
  renderSidebar();

  // Sidebar buttons.
  $("#btn-add").addEventListener("click", () => { state.selectedConnId = null; renderSidebar(); showView("grid"); });
  $("#btn-empty-add").addEventListener("click", () => { state.selectedConnId = null; renderSidebar(); showView("grid"); });
  $("#btn-remove").addEventListener("click", async () => {
    if (!state.selectedConnId) return;
    const c = state.connections.find((x) => x.id === state.selectedConnId);
    if (!confirm(`Remove "${c ? c.name : "connection"}"?`)) return;
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
  $("#conn-form").addEventListener("submit", (e) => { e.preventDefault(); saveAndMount(); });
  $("#btn-test").addEventListener("click", testConnection);
  $("#btn-cancel").addEventListener("click", () => {
    if (state.connections.length) showView("empty"); else showView("grid");
  });

  // Browser toolbar.
  $("#nav-up").addEventListener("click", () => browse(parentPath(state.browserPath)));
  $("#btn-refresh").addEventListener("click", () => browse(state.browserPath));
  $("#btn-upload").addEventListener("click", upload);
  $("#btn-newfolder").addEventListener("click", newFolder);
  $("#btn-delete").addEventListener("click", deleteSelected);

  // Modal.
  $("#modal-close").addEventListener("click", () => $("#modal").classList.add("hidden"));
  $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("#modal").classList.add("hidden"); });
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
