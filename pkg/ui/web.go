// Copyright 2018 Adam Shannon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ui

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/adamdecaf/trustprune/pkg/allowlist"
	"github.com/adamdecaf/trustprune/pkg/certutil"
	"github.com/adamdecaf/trustprune/pkg/ui/server"
)

const (
	statusValidLabel    = "Valid"
	statusExpiringLabel = "Expiring soon"
	statusExpiredLabel  = "Expired"
	statusNotYetLabel   = "Not yet valid"

	statusValidClass    = "valid"
	statusExpiringClass = "expiring"
	statusExpiredClass  = "expired"
	statusNotYetClass   = "notyet"
)

// certExpiringWithin is the "Expiring soon" window and the
// "Expiring within 90 days" filter. It is 90 days of 24 hours.
const certExpiringWithin = 90 * 24 * time.Hour

const (
	// head is the document start and stylesheet. The page is self-contained:
	// system fonts, inline CSS, no images, and no network requests. The local
	// server sets no Content-Security-Policy. Inline style and script are the
	// whole page, so a policy that allows those and blocks remote hosts still
	// works. The stylesheet must not contain "}}" — that ends a Go template
	// action — and must not reference a remote URL.
	head = `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>trustprune {{.Operation}}</title>
<style>
:root {
  color-scheme: light;
  --bg: #f3f0e8;
  --header: rgba(243, 240, 232, 0.94);
  --card: #fffcf7;
  --text: #1c1915;
  --muted: #5c564c;
  --border: #e3dcd0;
  --border-strong: #cfc6b6;
  --accent: #1e4d3a;
  --on-accent: #f4fbf6;
  --focus: #1e4d3a;
  --chip: #fffcf7;
  --switch-off: #d5cfc3;
  --switch-on: #1e4d3a;
  --knob: #ffffff;
  --knob-on: #ffffff;
  --code-bg: #f3eee4;
  --dropped: #f6f3ec;
  --keep: #1e4d3a;
  --danger: #991b1b;
  --shadow: 0 1px 2px rgba(28, 25, 21, 0.05), 0 10px 28px rgba(28, 25, 21, 0.05);
  --header-shadow: 0 10px 28px rgba(28, 25, 21, 0.06);
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #121614;
    --header: rgba(18, 22, 20, 0.94);
    --card: #1c2420;
    --text: #f4f1ea;
    --muted: #c4bcae;
    --border: #303a34;
    --border-strong: #465249;
    --accent: #9ed4b8;
    --on-accent: #10231a;
    --focus: #c6f0da;
    --chip: #1c2420;
    --switch-off: #3c4842;
    --switch-on: #9ed4b8;
    --knob: #f4fbf6;
    --knob-on: #10231a;
    --code-bg: #101614;
    --dropped: #171e1b;
    --keep: #9ed4b8;
    --danger: #fca5a5;
    --shadow: none;
    --header-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
  }
}
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 16px;
  line-height: 1.45;
}
:focus { outline: none; }
:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
.wrap {
  width: min(1080px, calc(100% - 2rem));
  margin: 0 auto;
}
.top {
  position: sticky;
  top: 0;
  z-index: 20;
  background: var(--header);
  border-bottom: 1px solid var(--border);
  box-shadow: var(--header-shadow);
  backdrop-filter: blur(12px);
}
.top-inner {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 1rem 0 0.9rem;
}
.title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1rem;
  flex-wrap: wrap;
}
.eyebrow {
  margin: 0;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--muted);
}
h1 {
  margin: 0.1rem 0 0;
  font-size: 1.65rem;
  line-height: 1.15;
  letter-spacing: -0.02em;
}
.counts {
  margin: 0.3rem 0 0;
  color: var(--muted);
  font-size: 0.95rem;
}
.note {
  margin: 0;
  max-width: 68rem;
  color: var(--muted);
  font-size: 0.9rem;
}
.actions, .select-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
}
.btn, .chip, select, input[type="search"], .fp-copy {
  font: inherit;
  color: var(--text);
}
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2.5rem;
  padding: 0.45rem 0.9rem;
  border: 1px solid var(--border-strong);
  border-radius: 10px;
  background: var(--card);
  color: var(--text);
  text-decoration: none;
  font-weight: 700;
  cursor: pointer;
}
.btn.primary {
  background: var(--accent);
  border-color: transparent;
  color: var(--on-accent);
}
.btn:hover, .chip:hover, .fp-copy:hover { border-color: var(--keep); }
.btn.primary:hover { filter: brightness(1.08); }
.controls {
  display: flex;
  flex-wrap: wrap;
  gap: 0.65rem 0.75rem;
  align-items: flex-end;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.28rem;
  min-width: 9rem;
}
.field.grow { flex: 1 1 16rem; }
.field.sort { flex: 0 1 12rem; }
.field label {
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--muted);
}
input[type="search"], select {
  width: 100%;
  min-height: 2.5rem;
  padding: 0.45rem 0.7rem;
  border: 1px solid var(--border-strong);
  border-radius: 10px;
  background: var(--card);
  color: var(--text);
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}
.chip {
  min-height: 2.25rem;
  padding: 0.3rem 0.75rem;
  border: 1px solid var(--border-strong);
  border-radius: 999px;
  background: var(--chip);
  font-size: 0.86rem;
  font-weight: 700;
  cursor: pointer;
}
.chip[aria-pressed="true"] {
  background: var(--accent);
  border-color: transparent;
  color: var(--on-accent);
}
.filter-note {
  margin: 0;
  color: var(--muted);
  font-size: 0.85rem;
}
main.wrap { padding: 1rem 0 3rem; }
#cert-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
article.cert {
  background: var(--card);
  border: 1px solid var(--border);
  border-left: 3px solid var(--keep);
  border-radius: 14px;
  padding: 0.9rem 1rem 0.8rem;
  box-shadow: var(--shadow);
}
/* Dropped look follows the live checkbox, with or without the page script.
   :has() is more specific than .is-dropped, so a stale initial class cannot
   keep the dropped card or the strikethrough after the box is checked.
   Browsers without :has() ignore these rules. */
article.cert:has(input.cert-keep:not(:checked)) {
  background: var(--dropped);
  border-left-color: var(--border-strong);
}
article.cert:has(input.cert-keep:not(:checked)) .subject {
  color: var(--muted);
  text-decoration: line-through;
}
article.cert:has(input.cert-keep:checked) {
  background: var(--card);
  border-left-color: var(--keep);
}
article.cert:has(input.cert-keep:checked) .subject {
  color: var(--text);
  text-decoration: none;
}
@supports not selector(:has(*)) {
  article.cert.is-dropped {
    background: var(--dropped);
    border-left-color: var(--border-strong);
  }
  article.cert.is-dropped .subject {
    color: var(--muted);
    text-decoration: line-through;
  }
}
.cert-main {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  grid-template-areas: "switch identity" "switch meta";
  gap: 0.35rem 0.9rem;
  align-items: center;
}
.switch { grid-area: switch; }
.identity { grid-area: identity; min-width: 0; }
.meta {
  grid-area: meta;
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem 0.7rem;
  align-items: center;
}
@media (min-width: 900px) {
  .cert-main {
    grid-template-columns: auto minmax(0, 1fr) auto;
    grid-template-areas: "switch identity meta";
  }
  .meta { justify-content: flex-end; }
}
.switch {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  cursor: pointer;
  user-select: none;
}
.switch input {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
.track {
  width: 2.35rem;
  height: 1.35rem;
  border-radius: 999px;
  background: var(--switch-off);
  border: 1px solid var(--border-strong);
  position: relative;
  flex: none;
}
.track::after {
  content: "";
  position: absolute;
  top: 1px;
  left: 1px;
  width: 1rem;
  height: 1rem;
  border-radius: 50%;
  background: var(--knob);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.28);
  transition: transform 0.15s ease;
}
.switch input:checked + .track {
  background: var(--switch-on);
  border-color: transparent;
}
.switch input:checked + .track::after {
  transform: translateX(1rem);
  background: var(--knob-on);
}
.switch input:focus-visible + .track {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
.switch-name { font-size: 0.82rem; font-weight: 700; color: var(--muted); }
.subject {
  margin: 0;
  font-size: 1.02rem;
  font-weight: 700;
  line-height: 1.3;
  overflow-wrap: anywhere;
}
.issuer {
  margin: 0.15rem 0 0;
  color: var(--muted);
  font-size: 0.88rem;
  overflow-wrap: anywhere;
}
.badge {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 0.16rem 0.55rem;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.01em;
  line-height: 1.35;
  white-space: nowrap;
}
.badge-valid { background: #166534; color: #f0fdf4; }
.badge-expiring { background: #92400e; color: #fffbeb; }
.badge-expired { background: #991b1b; color: #fef2f2; }
.badge-notyet { background: #334155; color: #f8fafc; }
.pill {
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--muted);
  border: 1px solid var(--border-strong);
  border-radius: 999px;
  padding: 0.12rem 0.5rem;
  white-space: nowrap;
}
.expiry {
  color: var(--muted);
  font-size: 0.88rem;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.expiry-label { margin-right: 0.25rem; }
.fp-copy {
  font-family: var(--mono);
  font-size: 0.82rem;
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.28rem 0.5rem;
  cursor: pointer;
}
.fp-copy code { font-family: inherit; }
.fp-copy[data-copied="1"] { border-color: var(--keep); box-shadow: inset 0 0 0 1px var(--keep); }
.fp-copy[data-copied="1"]::after {
  content: "Copied";
  margin-left: 0.45rem;
  font-family: var(--sans);
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--keep);
}
.fp-copy[data-copy-failed="1"] { border-color: var(--danger); box-shadow: inset 0 0 0 1px var(--danger); }
.fp-copy[data-copy-failed="1"]::after {
  content: "Copy failed";
  margin-left: 0.45rem;
  font-family: var(--sans);
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--danger);
}
.cert-details {
  margin-top: 0.75rem;
  border-top: 1px solid var(--border);
  padding-top: 0.55rem;
}
summary {
  width: fit-content;
  cursor: pointer;
  font-weight: 700;
  color: var(--keep);
}
.kv {
  list-style: none;
  margin: 0.7rem 0 0;
  padding: 0;
}
.kv li {
  padding: 0.28rem 0;
  border-bottom: 1px solid var(--border);
  overflow-wrap: anywhere;
  font-size: 0.9rem;
}
.kv li:last-child { border-bottom: 0; }
pre.raw {
  margin: 0.75rem 0 0.15rem;
  padding: 0.85rem 1rem;
  overflow: auto;
  max-height: 22rem;
  background: var(--code-bg);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 10px;
  font-family: var(--mono);
  font-size: 0.78rem;
  line-height: 1.45;
  white-space: pre-wrap;
}
.empty {
  margin: 0;
  padding: 1.5rem 1rem;
  text-align: center;
  background: var(--card);
  border: 1px dashed var(--border-strong);
  border-radius: 14px;
}
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  .track::after { transition: none; }
  .btn.primary:hover { filter: none; }
}
</style>
</head>
<body>
`
	// footer is the page script. It stays inline and does not fetch anything.
	// renderAllowlistJSON matches checklistAllowlistJSON (fingerprints,
	// two-space indent, trailing newline, {} when nothing is checked).
	// Sorting reorders rows in the document so keyboard and screen-reader
	// order follow the chosen column. Checked fingerprints are taken from
	// each checkbox value, and from the embedded list when that value still
	// matches, so a reorder does not pair a box with a different fingerprint.
	// The script must not contain "}}" — that ends a Go template action.
	footer = `
<script>
function renderAllowlistJSON(fps) {
  var payload = {};
  if (fps.length > 0) {
    payload.fingerprints = fps;
  }
  return JSON.stringify(payload, null, 2) + "\n";
}

function checkedFingerprints() {
  var boxes = document.querySelectorAll("input.cert-keep");
  var fps = [];
  var embedded = document.getElementById("checklist-fingerprints");
  var fromJSON = null;
  if (embedded && embedded.value) {
    try {
      fromJSON = JSON.parse(embedded.value);
    } catch (e) {
      fromJSON = null;
    }
  }
  for (var i = 0; i < boxes.length; i++) {
    if (!boxes[i].checked) {
      continue;
    }
    var fp = boxes[i].value;
    if (fromJSON && fromJSON.length == boxes.length && fromJSON[i] == fp) {
      fps.push(fromJSON[i]);
    } else if (fromJSON && fromJSON.length == boxes.length) {
      var found = fp;
      var j;
      for (j = 0; j < fromJSON.length; j++) {
        if (fromJSON[j] == fp) {
          found = fromJSON[j];
          break;
        }
      }
      fps.push(found);
    } else {
      fps.push(fp);
    }
  }
  return fps;
}

var checklistDirty = false;

function allowlistText() {
  var embedded = document.getElementById("checklist-allowlist");
  if (!checklistDirty && embedded && embedded.value) {
    return embedded.value;
  }
  return renderAllowlistJSON(checkedFingerprints());
}

function downloadAllowlist() {
  var text = allowlistText();
  var blob = new Blob([text], {type: "application/json"});
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = "allowlist.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function countText(total, kept) {
  var drop = total - kept;
  if (drop < 0) {
    drop = 0;
  }
  var noun = "certificates";
  if (total == 1) {
    noun = "certificate";
  }
  return total + " " + noun + ", " + kept + " kept, " + drop + " to drop";
}

function updateCounts() {
  var el = document.getElementById("counts");
  if (!el) {
    return;
  }
  var boxes = document.querySelectorAll("input.cert-keep");
  var kept = 0;
  var i;
  for (i = 0; i < boxes.length; i++) {
    if (boxes[i].checked) {
      kept++;
    }
  }
  el.textContent = countText(boxes.length, kept);
}

function rowOf(input) {
  var n = input;
  while (n && n !== document.body) {
    if (n.classList && n.classList.contains("cert")) {
      return n;
    }
    n = n.parentNode;
  }
  return null;
}

function syncDropped(row) {
  if (!row) {
    return;
  }
  var box = row.querySelector("input.cert-keep");
  if (!box) {
    return;
  }
  if (box.checked) {
    row.classList.remove("is-dropped");
  } else {
    row.classList.add("is-dropped");
  }
}

var activeFilter = "all";

function applyView() {
  var search = document.getElementById("cert-search");
  var q = "";
  if (search && search.value) {
    q = search.value.toLowerCase().trim();
  }
  var rows = document.querySelectorAll("article.cert");
  var shown = 0;
  var i;
  for (i = 0; i < rows.length; i++) {
    var row = rows[i];
    var box = row.querySelector("input.cert-keep");
    var keep = !!(box && box.checked);
    var status = row.getAttribute("data-status") || "";
    var selfSigned = row.getAttribute("data-self") == "1";
    var hay = ((row.getAttribute("data-subject") || "") + "\n" + (row.getAttribute("data-issuer") || "") + "\n" + (row.getAttribute("data-fp") || "")).toLowerCase();
    var ok = true;
    if (q && hay.indexOf(q) < 0) {
      ok = false;
    }
    if (ok && activeFilter == "kept" && !keep) {
      ok = false;
    }
    if (ok && activeFilter == "dropped" && keep) {
      ok = false;
    }
    if (ok && activeFilter == "expired" && status != "expired") {
      ok = false;
    }
    if (ok && activeFilter == "expiring" && status != "expiring") {
      ok = false;
    }
    if (ok && activeFilter == "selfsigned" && !selfSigned) {
      ok = false;
    }
    row.hidden = !ok;
    if (ok) {
      shown++;
    }
  }
  var note = document.getElementById("filter-note");
  if (!note) {
    return;
  }
  if (q || activeFilter != "all") {
    note.hidden = false;
    note.textContent = "Showing " + shown + " of " + rows.length;
  } else {
    note.hidden = true;
    note.textContent = "";
  }
}

function sortValue(row, key) {
  if (key == "notafter") {
    return row.getAttribute("data-notafter") || "";
  }
  if (key == "issuer") {
    return (row.getAttribute("data-issuer") || "").toLowerCase();
  }
  return (row.getAttribute("data-subject") || "").toLowerCase();
}

function sortRows() {
  var sel = document.getElementById("cert-sort");
  var list = document.getElementById("cert-list");
  if (!list) {
    return;
  }
  var key = sel ? sel.value : "subject";
  var rows = Array.prototype.slice.call(list.querySelectorAll("article.cert"));
  rows.sort(function (a, b) {
    var av = sortValue(a, key);
    var bv = sortValue(b, key);
    if (av < bv) {
      return -1;
    }
    if (av > bv) {
      return 1;
    }
    var ai = parseInt(a.getAttribute("data-idx") || "0", 10);
    var bi = parseInt(b.getAttribute("data-idx") || "0", 10);
    return ai - bi;
  });
  var i;
  for (i = 0; i < rows.length; i++) {
    list.appendChild(rows[i]);
  }
}

function setVisibleKeep(checked) {
  var rows = document.querySelectorAll("article.cert");
  var i;
  for (i = 0; i < rows.length; i++) {
    if (rows[i].hidden) {
      continue;
    }
    var box = rows[i].querySelector("input.cert-keep");
    if (!box) {
      continue;
    }
    if (box.checked != checked) {
      box.checked = checked;
      checklistDirty = true;
    }
    syncDropped(rows[i]);
  }
  updateCounts();
  applyView();
}

function fallbackCopy(text) {
  var ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  var ok = false;
  try {
    ok = document.execCommand("copy") == true;
  } catch (e) {
    ok = false;
  }
  if (ta.parentNode) {
    ta.parentNode.removeChild(ta);
  }
  return ok;
}

function copyFingerprint(btn) {
  var fp = btn.getAttribute("data-fp") || "";
  if (!fp) {
    return;
  }
  var status = document.getElementById("copy-status");
  function clearCopyState() {
    btn.removeAttribute("data-copied");
    btn.removeAttribute("data-copy-failed");
    if (status) {
      status.textContent = "";
    }
  }
  function done() {
    btn.removeAttribute("data-copy-failed");
    btn.setAttribute("data-copied", "1");
    if (status) {
      status.textContent = "Copied SHA256 fingerprint";
    }
    window.setTimeout(clearCopyState, 1200);
  }
  function failed() {
    btn.removeAttribute("data-copied");
    btn.setAttribute("data-copy-failed", "1");
    if (status) {
      status.textContent = "Copy failed";
    }
    window.setTimeout(clearCopyState, 1200);
  }
  function finish(ok) {
    if (ok) {
      done();
    } else {
      failed();
    }
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(fp).then(done, function () {
      finish(fallbackCopy(fp));
    });
    return;
  }
  finish(fallbackCopy(fp));
}

var downloadBtn = document.getElementById("download-allowlist");
if (downloadBtn) {
  downloadBtn.addEventListener("click", downloadAllowlist);
}
var keepBoxes = document.querySelectorAll("input.cert-keep");
var bi;
for (bi = 0; bi < keepBoxes.length; bi++) {
  keepBoxes[bi].addEventListener("change", function () {
    checklistDirty = true;
    syncDropped(rowOf(this));
    updateCounts();
    applyView();
  });
}
var chips = document.querySelectorAll(".chip");
for (bi = 0; bi < chips.length; bi++) {
  chips[bi].addEventListener("click", function () {
    activeFilter = this.getAttribute("data-filter") || "all";
    var j;
    for (j = 0; j < chips.length; j++) {
      chips[j].setAttribute("aria-pressed", chips[j] == this ? "true" : "false");
    }
    applyView();
  });
}
var searchBox = document.getElementById("cert-search");
if (searchBox) {
  searchBox.addEventListener("input", applyView);
}
var sortSel = document.getElementById("cert-sort");
if (sortSel) {
  sortSel.addEventListener("change", sortRows);
}
var selectAllBtn = document.getElementById("select-all");
if (selectAllBtn) {
  selectAllBtn.addEventListener("click", function () { setVisibleKeep(true); });
}
var selectNoneBtn = document.getElementById("select-none");
if (selectNoneBtn) {
  selectNoneBtn.addEventListener("click", function () { setVisibleKeep(false); });
}
var copyButtons = document.querySelectorAll(".fp-copy");
for (bi = 0; bi < copyButtons.length; bi++) {
  copyButtons[bi].addEventListener("click", function () { copyFingerprint(this); });
}
</script>
</body></html>`

	list = `
<textarea id="checklist-allowlist" hidden readonly>{{.AllowlistJSON}}</textarea>
<textarea id="checklist-fingerprints" hidden readonly>{{.FingerprintsJSON}}</textarea>
<header class="top">
  <div class="wrap top-inner">
    <div class="title-row">
      <div>
        <p class="eyebrow">trustprune</p>
        <h1>Certificates</h1>
        <p id="counts" class="counts">{{.CountLine}}</p>
      </div>
      <div class="actions">
        <button type="button" class="btn primary" id="download-allowlist">Download allowlist</button>
        <a class="btn" href="/done">Close</a>
      </div>
    </div>
    <p class="note">Checked certificates are kept. Download allowlist saves a JSON allowlist in this browser. The page leaves the trust store unchanged.</p>
    <div class="controls">
      <div class="field grow">
        <label for="cert-search">Search</label>
        <input id="cert-search" type="search" placeholder="Subject, issuer, or SHA256" autocomplete="off" spellcheck="false">
      </div>
      <div class="field sort">
        <label for="cert-sort">Sort</label>
        <select id="cert-sort">
          <option value="subject" selected>Subject</option>
          <option value="notafter">NotAfter</option>
          <option value="issuer">Issuer</option>
        </select>
      </div>
      <div class="select-actions">
        <button type="button" class="btn" id="select-all" title="Check every certificate that is currently shown">Select all</button>
        <button type="button" class="btn" id="select-none" title="Uncheck every certificate that is currently shown">Select none</button>
      </div>
    </div>
    <div class="chips" role="group" aria-label="Filter certificates">
      <button type="button" class="chip" data-filter="all" aria-pressed="true">All</button>
      <button type="button" class="chip" data-filter="kept" aria-pressed="false">Kept</button>
      <button type="button" class="chip" data-filter="dropped" aria-pressed="false">Dropped</button>
      <button type="button" class="chip" data-filter="expired" aria-pressed="false">Expired</button>
      <button type="button" class="chip" data-filter="expiring" aria-pressed="false">Expiring within 90 days</button>
      <button type="button" class="chip" data-filter="selfsigned" aria-pressed="false">Self-signed</button>
    </div>
    <p id="filter-note" class="filter-note" aria-live="polite" hidden></p>
    <noscript><p class="note">Search, filters, sort, copy, and download need JavaScript. The keep switches below work without it.</p></noscript>
  </div>
</header>
<p id="copy-status" class="sr-only" aria-live="polite"></p>
<main class="wrap" id="cert-list">
{{range $idx, $cert := .Certificates}}
<article class="cert{{ if not $cert.Keep }} is-dropped{{ end }}" data-idx="{{ $idx }}" data-subject="{{ $cert.Subject }}" data-issuer="{{ $cert.Issuer }}" data-fp="{{ $cert.Fingerprint }}" data-status="{{ $cert.StatusClass }}" data-self="{{ if $cert.SelfSigned }}1{{ else }}0{{ end }}" data-notafter="{{ $cert.NotAfter }}">
  <div class="cert-main">
    <label class="switch">
      <input type="checkbox" class="cert-keep" value="{{ $cert.Fingerprint }}"{{ if $cert.Keep }} checked{{ end }}>
      <span class="track" aria-hidden="true"></span>
      <span class="switch-name">Keep</span>
    </label>
    <div class="identity">
      <h2 class="subject">{{ $cert.Subject }}</h2>
      <p class="issuer">{{ $cert.Issuer }}</p>
    </div>
    <div class="meta">
      <span class="badge badge-{{ $cert.StatusClass }}">{{ $cert.Status }}</span>
      {{ if $cert.SelfSigned }}<span class="pill">Self-signed</span>{{ end }}
      <div class="expiry"><span class="expiry-label">Not after</span> <time datetime="{{ $cert.NotAfter }}">{{ $cert.NotAfter }}</time></div>
      <button type="button" class="fp-copy" data-fp="{{ $cert.Fingerprint }}" title="Copy full SHA256" aria-label="Copy SHA256 fingerprint {{ $cert.Fingerprint }}"><code>{{ $cert.FingerprintShort }}</code></button>
    </div>
  </div>
  <details class="cert-details">
    <summary>Details</summary>
    <ul class="kv">
      <li>Subject: {{ $cert.Subject }}</li>
      <li>Issuer: {{ $cert.Issuer }}</li>
      <li>SHA256: {{ $cert.Fingerprint }}</li>
      <li>Serial: {{ $cert.Serial }}</li>
      <li>NotBefore: {{ $cert.NotBefore }}</li>
      <li>NotAfter: {{ $cert.NotAfter }}</li>
    </ul>
    <pre class="raw">{{ $cert.Raw }}</pre>
  </details>
</article>
{{else}}
<p class="empty"><strong>No certificates</strong></p>
{{end}}
</main>
`
)

func launch() (err error) {
	server.Register()
	server.Start()
	defer func() {
		err2 := server.Stop()
		if err == nil {
			err = err2
		}
	}()
	err = Open()
	return err
}

func write(w io.Writer, tpl string, data interface{}) error {
	t := template.Must(template.New("contents").Parse(tpl))
	err := t.Execute(w, data)
	if err != nil {
		_, _ = io.WriteString(w, fmt.Sprintf("ERROR: %v", err))
		return err
	}
	return nil
}

// writePrinterFailure reports a printer error and still offers Close so /done is reachable.
func writePrinterFailure(w io.Writer, err error) {
	_, _ = io.WriteString(w, fmt.Sprintf(`<p>ERROR: %v</p>
Options: <a href="/done" style="color: #000;">Close</a>
`, err))
	_ = write(w, footer, nil)
}

// webCert is one certificate row in the web list UI.
// Keep is the checkbox: checked means the certificate stays in the allowlist.
// Status and StatusClass are computed with certValidity so the badge does not
// depend on the page script.
type webCert struct {
	Subject          string
	Issuer           string
	Fingerprint      string
	FingerprintShort string
	Serial           string
	NotBefore        string
	NotAfter         string
	Raw              string
	Keep             bool
	Status           string
	StatusClass      string
	SelfSigned       bool
}

// webListData is the list page.
// AllowlistJSON is the allowlist file for certificates that start checked.
// FingerprintsJSON is every fingerprint in display order. The page script
// reads it when a checkbox changes and a new allowlist is built.
// CountLine is the header summary ("N certificates, K kept, D to drop").
type webListData struct {
	Certificates     []webCert
	AllowlistJSON    string
	FingerprintsJSON string
	CountLine        string
}

// certValidity classifies a certificate against now.
// Expired wins when now is after NotAfter.
// Not yet valid means now is before NotBefore.
// Expiring soon means the certificate is inside its validity and NotAfter
// is within certExpiringWithin, including the exact boundary.
// Otherwise the certificate is Valid. now equal to NotAfter is still inside
// the certificate's validity, so it is Expiring soon rather than Expired.
func certValidity(notBefore, notAfter, now time.Time) (label, class string) {
	if now.After(notAfter) {
		return statusExpiredLabel, statusExpiredClass
	}
	if now.Before(notBefore) {
		return statusNotYetLabel, statusNotYetClass
	}
	if notAfter.Sub(now) <= certExpiringWithin {
		return statusExpiringLabel, statusExpiringClass
	}
	return statusValidLabel, statusValidClass
}

// certSelfSigned reports a self-issued certificate: the subject and issuer
// distinguished names use the same encoding. Signature verification is not
// required, so a legacy root whose algorithm Go cannot check still matches
// the Self-signed filter.
func certSelfSigned(c *x509.Certificate) bool {
	if c == nil || len(c.RawSubject) == 0 || len(c.RawIssuer) == 0 {
		return false
	}
	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

// shortFingerprint is the monospace preview. The full value stays on the
// copy button and in the details list.
func shortFingerprint(fp string) string {
	const headN, tailN = 8, 8
	if len(fp) < headN+tailN+1 {
		return fp
	}
	return fp[:headN] + "…" + fp[len(fp)-tailN:]
}

// checklistCountText is the sticky-header summary. The page script uses the
// same words when a keep switch changes.
func checklistCountText(total, kept int) string {
	drop := total - kept
	if drop < 0 {
		drop = 0
	}
	noun := "certificates"
	if total == 1 {
		noun = "certificate"
	}
	return fmt.Sprintf("%d %s, %d kept, %d to drop", total, noun, kept, drop)
}

func webCertFromX509At(c *x509.Certificate, raw string, now time.Time) webCert {
	fp := certutil.GetHexSHA256Fingerprint(*c)
	label, class := certValidity(c.NotBefore, c.NotAfter, now)
	return webCert{
		Subject:          certutil.StringifyPKIXName(c.Subject),
		Issuer:           certutil.StringifyPKIXName(c.Issuer),
		Fingerprint:      fp,
		FingerprintShort: shortFingerprint(fp),
		Serial:           c.SerialNumber.String(),
		NotBefore:        c.NotBefore.UTC().Format("2006-01-02"),
		NotAfter:         c.NotAfter.UTC().Format("2006-01-02"),
		Raw:              raw,
		Status:           label,
		StatusClass:      class,
		SelfSigned:       certSelfSigned(c),
	}
}

func webCertFromX509(c *x509.Certificate, raw string) webCert {
	return webCertFromX509At(c, raw, time.Now())
}

// prepareWebAllowlist loads cfg.AllowlistPath. A nil allowlist means every
// certificate starts checked. The allowlist is not applied to a trust store.
func prepareWebAllowlist(cfg *Config) (*allowlist.Allowlist, error) {
	if cfg == nil {
		return nil, nil
	}
	path := strings.TrimSpace(cfg.AllowlistPath)
	if path == "" {
		return nil, nil
	}
	al, err := allowlist.FromPathOrURL(path, allowlist.FetchOptions{
		SHA256:    cfg.AllowlistSHA256,
		Signature: cfg.AllowlistSignature,
		PubKey:    cfg.AllowlistPubKey,
	})
	if err != nil {
		return nil, fmt.Errorf("list --allowlist: %w", err)
	}
	return &al, nil
}

// certPrechecked reports whether the checklist box starts checked.
// A nil allowlist keeps every certificate. Otherwise the box follows
// Allowlist.Matches, the same decision allowlist --file would make.
func certPrechecked(al *allowlist.Allowlist, cert *x509.Certificate) bool {
	if al == nil {
		return true
	}
	return al.Matches(cert)
}

// checklistAllowlistJSON is the allowlist file the web checklist downloads.
// Bytes match allowlist.ToFile for a .json path: a fingerprints array,
// two-space indent, and a trailing newline. An empty selection is {}.
func checklistAllowlistJSON(fingerprints []string) ([]byte, error) {
	al := allowlist.Allowlist{}
	if len(fingerprints) > 0 {
		al.Fingerprints = append([]string(nil), fingerprints...)
	}
	out, err := json.MarshalIndent(al, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// checklistFingerprintsJSON is the display-order fingerprint list embedded
// for the page script. It is a JSON array, [] when there are no certificates.
func checklistFingerprintsJSON(fingerprints []string) (string, error) {
	if fingerprints == nil {
		fingerprints = []string{}
	}
	out, err := json.Marshal(fingerprints)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// applyChecklist builds the list page from certs in their current order.
// raws[i] is the formatted dump for certs[i]. al nil checks every box.
func applyChecklist(certs []*x509.Certificate, raws []string, al *allowlist.Allowlist) (webListData, error) {
	contents := make([]webCert, len(certs))
	all := make([]string, 0, len(certs))
	kept := make([]string, 0, len(certs))
	for i := range certs {
		raw := ""
		if i < len(raws) {
			raw = raws[i]
		}
		contents[i] = webCertFromX509(certs[i], raw)
		contents[i].Keep = certPrechecked(al, certs[i])
		all = append(all, contents[i].Fingerprint)
		if contents[i].Keep {
			kept = append(kept, contents[i].Fingerprint)
		}
	}
	js, err := checklistAllowlistJSON(kept)
	if err != nil {
		return webListData{}, err
	}
	fps, err := checklistFingerprintsJSON(all)
	if err != nil {
		return webListData{}, err
	}
	return webListData{
		Certificates:     contents,
		AllowlistJSON:    string(js),
		FingerprintsJSON: fps,
		CountLine:        checklistCountText(len(contents), len(kept)),
	}, nil
}

func showCertsOnWeb(certs []*x509.Certificate, cfg *Config) error {
	al, err := prepareWebAllowlist(cfg)
	if err != nil {
		return err
	}

	server.Register()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, ok := getPrinter(cfg.Format)
		if !ok {
			_, _ = io.WriteString(w, UnknownFormatError(cfg.Format).Error())
			return
		}
		defer p.close()

		err := write(w, head, struct {
			Operation string
		}{
			Operation: "list certificates",
		})
		if err != nil {
			return
		}

		// sort certs by Subject
		certutil.Sort(certs)

		raws := make([]string, len(certs))
		for i := range certs {
			var buf bytes.Buffer
			w1 := bufio.NewWriter(&buf)

			if err := p.write(w1, certs[i:i+1]); err != nil {
				writePrinterFailure(w, err)
				return
			}
			_ = w1.Flush()
			raws[i] = buf.String()
		}
		data, err := applyChecklist(certs, raws, al)
		if err != nil {
			writePrinterFailure(w, err)
			return
		}
		_ = write(w, list, data)
		_ = write(w, footer, nil)
	})

	return launch()
}
