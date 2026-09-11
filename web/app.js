(() => {
  "use strict";
  const $ = (s) => document.querySelector(s),
    $$ = (s) => [...document.querySelectorAll(s)];
  let packets = [],
    capture = null,
    stats = { conversations: [], endpoints: [], devices: [], protocols: {} };
  const esc = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const fmtBytes = (n) => {
    n = Number(n) || 0;
    for (const u of ["B", "KB", "MB", "GB"]) {
      if (n < 1024) return `${n.toFixed(u === "B" ? 0 : 1)} ${u}`;
      n /= 1024;
    }
    return `${n.toFixed(1)} TB`;
  };
  const time = (t) =>
    new Date(t).toLocaleTimeString("de-DE", {
      hour12: false,
      fractionalSecondDigits: 3,
    });
  async function api(url, options = {}) {
    const r = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    if (!r.ok) {
      let x;
      try {
        x = await r.json();
      } catch {
        x = { error: await r.text() };
      }
      throw Error(x.error || `HTTP ${r.status}`);
    }
    return r.status === 204 ? null : r.json();
  }
  function alert(message) {
    $("#alert").textContent = message;
    $("#alert").classList.toggle("hidden", !message);
  }
  function table(headers, rows) {
    return `<div class="data-table"><table><thead><tr>${headers.map((x) => `<th>${esc(x)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
  }
  function packetRow(p, full = true) {
    return `<tr data-packet="${p.id}"><td>${p.id}</td><td>${time(p.timestamp)}</td><td>${esc(p.srcIp || p.srcMac || "")}</td><td>${esc(p.dstIp || p.dstMac || "")}</td><td>${esc(p.applicationProtocol || p.transportProtocol || "")}</td>${full ? `<td>${p.srcPort || ""}</td><td>${p.dstPort || ""}</td>` : `<td>${p.srcPort || ""} → ${p.dstPort || ""}</td>`}<td>${p.length}</td><td title="${esc(p.info)}">${esc(p.info || "")}</td></tr>`;
  }
  function renderPackets() {
    const list = packets.slice(-1500);
    $("#packetRows").innerHTML = list.map((p) => packetRow(p)).join("");
    $("#allPacketRows").innerHTML = list
      .map((p) => packetRow(p, false))
      .join("");
    $("#visibleCount").textContent =
      `${packets.length.toLocaleString("de-DE")} im Speicher`;
    const box = $(".packet-table");
    if (box && box.scrollHeight - box.scrollTop - box.clientHeight < 250)
      box.scrollTop = box.scrollHeight;
  }
  let setupText = "";
  async function refreshStatus() {
    try {
      const s = await api("/api/status");
      capture = s.capture;
      const d = s.dependencies || {};
      $("#dot").className = d.ready ? "ok" : "bad";
      $("#statusText").textContent = d.ready
        ? capture
          ? `Capture: ${capture.status}`
          : "Bereit"
        : "Einrichtung erforderlich";
      const rows = [
        ["tshark", d.tshark],
        ["dumpcap", d.dumpcap],
        ["Capture-Rechte", d.capturePermission],
      ];
      $("#dependencyStatus").innerHTML = rows
        .map(
          ([n, x]) =>
            `<p>${n}: <b class="${x?.available ? "ok-text" : "bad-text"}">${x?.available ? "✓ " + esc(x.version || "bereit") : "✗ " + esc(x?.error || "fehlt")}</b></p>`,
        )
        .join("");
      $("#setupChecklist").innerHTML = rows
        .map(
          ([n, x]) =>
            `<p><b class="${x?.available ? "ok-text" : "bad-text"}">${x?.available ? "✓" : "✗"} ${esc(n)}</b> ${esc(x?.version || x?.error || "")}</p>`,
        )
        .join("");
      setupText = [
        ...(d.instructions?.install || []),
        ...(d.instructions?.permissions || []),
        ...(d.instructions?.verify || []),
      ].join("\n");
      $("#setupCommands").innerHTML = `<pre>${esc(setupText)}</pre>`;
      if (!d.ready)
        alert(
          "Einmalige Linux-Systemeinrichtung erforderlich. Siehe Einstellungen → Systemeinrichtung.",
        );
      else alert("");
      updateStats();
    } catch (e) {
      $("#dot").className = "bad";
      $("#statusText").textContent = "API nicht erreichbar";
      alert(e.message);
    }
  }
  async function loadInterfaces() {
    const list = await api("/api/interfaces");
    $("#iface").innerHTML = list
      .map(
        (i) =>
          `<option value="${esc(i.name)}">${esc(i.name)} · ${esc(i.status)} · ${esc(i.ipv4.join(", "))} · RX ${fmtBytes(i.rxBytes)} / TX ${fmtBytes(i.txBytes)}</option>`,
      )
      .join("");
  }
  async function loadPackets() {
    const x = await api("/api/packets?limit=10000");
    packets = x.items;
    renderPackets();
  }
  async function analytics() {
    const [conversations, endpoints, devices, protocols] = await Promise.all(
      ["conversations", "endpoints", "devices", "protocols"].map((x) =>
        api("/api/" + x),
      ),
    );
    stats = { conversations, endpoints, devices, protocols };
    $("#conversationsTable").innerHTML = table(
      [
        "Protokoll",
        "Endpoint A",
        "Port A",
        "Endpoint B",
        "Port B",
        "A → B",
        "B → A",
        "Bytes",
        "Dauer",
      ],
      conversations.map(
        (c) =>
          `<tr><td>${esc(c.protocol)}</td><td>${esc(c.endpointA)}</td><td>${c.portA || ""}</td><td>${esc(c.endpointB)}</td><td>${c.portB || ""}</td><td>${c.packetsAToB}</td><td>${c.packetsBToA}</td><td>${fmtBytes(c.bytesAToB + c.bytesBToA)}</td><td>${((c.lastAt - c.startedAt) / 1000).toFixed(1)} s</td></tr>`,
      ),
    );
    $("#endpointsTable").innerHTML = table(
      [
        "Adresse",
        "MAC",
        "Gesendet",
        "Empfangen",
        "TX",
        "RX",
        "Protokolle",
        "Ports",
      ],
      endpoints.map(
        (e) =>
          `<tr><td>${esc(e.address)}</td><td>${esc(e.mac || "")}</td><td>${e.packetsSent}</td><td>${e.packetsReceived}</td><td>${fmtBytes(e.bytesSent)}</td><td>${fmtBytes(e.bytesReceived)}</td><td>${esc(e.protocols.join(", "))}</td><td>${esc(e.ports.join(", "))}</td></tr>`,
      ),
    );
    $("#devicesTable").innerHTML = table(
      [
        "Adresse",
        "MAC",
        "Pakete TX/RX",
        "Traffic TX/RX",
        "Protokolle",
        "Kommuniziert mit",
      ],
      devices.map(
        (d) =>
          `<tr><td>${esc(d.address)}</td><td>${esc(d.mac || "")}</td><td>${d.packetsSent} / ${d.packetsReceived}</td><td>${fmtBytes(d.bytesSent)} / ${fmtBytes(d.bytesReceived)}</td><td>${esc(d.protocols.join(", "))}</td><td>${esc(d.peers.join(", "))}</td></tr>`,
      ),
    );
    const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]);
    $("#protocolTable").innerHTML = table(
      ["Protokoll", "Pakete"],
      entries.map(([p, n]) => `<tr><td>${esc(p)}</td><td>${n}</td></tr>`),
    );
    const max = Math.max(1, ...entries.map((x) => x[1]));
    $("#protocolChart").innerHTML = entries
      .slice(0, 12)
      .map(
        ([p, n]) =>
          `<div><b>${esc(p)}</b><span class="bar"><i style="width:${(n / max) * 100}%"></i></span><span>${n}</span></div>`,
      )
      .join("");
    updateStats();
  }
  function updateStats() {
    const count = capture?.packetCount || packets.length,
      bytes = capture?.byteCount || packets.reduce((s, p) => s + p.length, 0),
      seconds = capture
        ? Math.max(1, (Date.now() - capture.startedAt) / 1000)
        : 1;
    $("#statPackets").textContent = count.toLocaleString("de-DE");
    $("#statBytes").textContent = fmtBytes(bytes);
    $("#statPps").textContent = (count / seconds).toFixed(1);
    $("#statDevices").textContent = stats.devices.length;
    $("#statConvs").textContent = stats.conversations.length;
    $("#statRuntime").textContent = new Date(seconds * 1000)
      .toISOString()
      .slice(11, 19);
  }
  async function detail(id) {
    try {
      const x = await api("/api/packets/" + id);
      $("#detail").textContent = JSON.stringify(x.details, null, 2);
      $("#hex").textContent = x.hex;
    } catch (e) {
      alert(e.message);
    }
  }
  document.addEventListener("click", (e) => {
    const row = e.target.closest("[data-packet]");
    if (row) detail(row.dataset.packet);
  });
  $("#nav").onclick = (e) => {
    const b = e.target.closest("[data-page]");
    if (!b) return;
    $$("#nav button").forEach((x) => x.classList.toggle("active", x === b));
    $$(".page").forEach((x) =>
      x.classList.toggle("active", x.id === b.dataset.page),
    );
    $("#title").textContent = b.textContent.trim();
    if (
      ["conversations", "endpoints", "devices", "protocols"].includes(
        b.dataset.page,
      )
    )
      analytics();
    if (b.dataset.page === "captures") loadCaptures();
  };
  $("#start").onclick = async () => {
    try {
      capture = await api("/api/capture/start", {
        method: "POST",
        body: JSON.stringify({
          interface: $("#iface").value,
          captureFilter: $("#captureFilter").value,
          displayFilter: $("#displayFilter").value,
        }),
      });
      packets = [];
      renderPackets();
      alert("");
    } catch (e) {
      alert(e.message);
    }
  };
  $("#pause").onclick = () =>
    api("/api/capture/pause", { method: "POST" })
      .then((x) => (capture = x))
      .catch((e) => alert(e.message));
  $("#resume").onclick = () =>
    api("/api/capture/resume", { method: "POST" })
      .then((x) => (capture = x))
      .catch((e) => alert(e.message));
  $("#stop").onclick = () =>
    api("/api/capture/stop", { method: "POST" })
      .then((x) => (capture = x))
      .catch((e) => alert(e.message));
  $("#validate").onclick = async () => {
    try {
      const x = await api("/api/filter/validate", {
        method: "POST",
        body: JSON.stringify({ filter: $("#displayFilter").value }),
      });
      $("#filterResult").innerHTML = x.valid
        ? '<b class="ok-text">✓ Gültig</b>'
        : `<b class="bad-text">${esc(x.error)}</b>`;
    } catch (e) {
      alert(e.message);
    }
  };
  async function loadCaptures() {
    const files = await api("/api/captures");
    $("#captureFiles").innerHTML = table(
      ["Name", "Datum", "Größe", "Aktionen"],
      files.map(
        (f) =>
          `<tr><td>${esc(f.name)}</td><td>${new Date(f.modified).toLocaleString("de-DE")}</td><td>${fmtBytes(f.size)}</td><td class="actions-row"><a href="/api/captures/${encodeURIComponent(f.name)}/download"><button>Download</button></a><button data-analyze="${esc(f.name)}">Analysieren</button><button class="danger" data-delete="${esc(f.name)}">Löschen</button></td></tr>`,
      ),
    );
  }
  $("#captureFiles").onclick = async (e) => {
    const del = e.target.dataset.delete,
      analyze = e.target.dataset.analyze;
    try {
      if (del && confirm(`Capture ${del} wirklich löschen?`)) {
        await api("/api/captures/" + encodeURIComponent(del), {
          method: "DELETE",
        });
        loadCaptures();
      }
      if (analyze) {
        await api("/api/captures/" + encodeURIComponent(analyze) + "/analyze", {
          method: "POST",
          body: JSON.stringify({ limit: 10000 }),
        });
        await loadPackets();
        alert("Capture wurde analysiert.");
      }
    } catch (x) {
      alert(x.message);
    }
  };
  $("#refreshCaptures").onclick = loadCaptures;
  $("#uploadBtn").onclick = async () => {
    const file = $("#upload").files[0];
    if (!file) return alert("Bitte eine PCAP- oder PCAPNG-Datei wählen.");
    const body = new FormData();
    body.append("capture", file);
    try {
      const r = await fetch("/api/captures/import", { method: "POST", body });
      if (!r.ok) throw Error((await r.json()).error);
      await loadCaptures();
    } catch (e) {
      alert(e.message);
    }
  };
  $("#theme").onclick = () => document.body.classList.toggle("light");
  function connect() {
    const ws = new WebSocket(
      `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`,
    );
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.type === "packet.batch") {
        for (const p of m.data) {
          packets.push(p);
          if (packets.length > 100000) packets.shift();
        }
        renderPackets();
        updateStats();
      } else if (m.type === "status") {
        capture = m.data;
        refreshStatus();
      } else if (m.type === "error") alert(m.data.message);
    };
    ws.onclose = () => setTimeout(connect, 2000);
  }
  $("#copySetup").onclick = () =>
    navigator.clipboard
      .writeText(setupText)
      .then(() => alert("Einrichtungsbefehle wurden kopiert."))
      .catch((e) => alert(e.message));
  $("#recheckSetup").onclick = async () => {
    try {
      await api("/api/system/recheck", { method: "POST" });
      await refreshStatus();
    } catch (e) {
      alert(e.message);
    }
  };
  Promise.all([refreshStatus(), loadInterfaces(), loadPackets(), analytics()])
    .then(connect)
    .catch((e) => alert(e.message));
  setInterval(updateStats, 1000);
  setInterval(analytics, 5000);
  setInterval(() => loadPackets().catch(() => {}), 1500);
  setInterval(() => refreshStatus().catch(() => {}), 2000);
})();
