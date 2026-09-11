const severityChart = new Chart(document.getElementById("severityChart"), {
  type: "doughnut",
  data: { labels: ["HIGH", "MEDIUM", "LOW"], datasets: [{ data: [0, 0, 0], backgroundColor: ["#ff6b6b", "#ffd166", "#7bdff2"] }] },
  options: { plugins: { legend: { labels: { color: "#e8eefc" } } } },
});

const classChart = new Chart(document.getElementById("classChart"), {
  type: "bar",
  data: { labels: [], datasets: [{ label: "Alerts", data: [], backgroundColor: "#5eead4" }] },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: "#93a0bb" }, grid: { color: "#22304a" } },
      y: { ticks: { color: "#93a0bb" }, grid: { color: "#22304a" } },
    },
  },
});

const timeChart = new Chart(document.getElementById("timeChart"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "Alerts", data: [], borderColor: "#5eead4", tension: 0.3, fill: false }] },
  options: {
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: "#93a0bb" }, grid: { color: "#22304a" } },
      y: { ticks: { color: "#93a0bb" }, grid: { color: "#22304a" } },
    },
  },
});

function renderList(id, rows, emptyText) {
  const node = document.getElementById(id);
  if (!rows.length) {
    node.innerHTML = `<li><span>${emptyText}</span></li>`;
    return;
  }
  node.innerHTML = rows.map(([left, right]) => `<li><span>${left}</span><strong>${right}</strong></li>`).join("");
}

async function refresh() {
  const [stats, alerts] = await Promise.all([
    fetch("/api/stats").then((r) => r.json()),
    fetch("/api/alerts").then((r) => r.json()),
  ]);

  document.getElementById("kpi-total").textContent = stats.total;
  document.getElementById("kpi-high").textContent = stats.severity.HIGH || 0;
  document.getElementById("kpi-medium").textContent = stats.severity.MEDIUM || 0;
  document.getElementById("kpi-blocked").textContent = (stats.blocked || []).length;

  severityChart.data.datasets[0].data = [
    stats.severity.HIGH || 0,
    stats.severity.MEDIUM || 0,
    stats.severity.LOW || 0,
  ];
  severityChart.update();

  const classes = Object.entries(stats.classtype || {});
  classChart.data.labels = classes.map(([name]) => name);
  classChart.data.datasets[0].data = classes.map(([, count]) => count);
  classChart.update();

  timeChart.data.labels = (stats.timeline || []).map(([stamp]) => stamp.slice(11));
  timeChart.data.datasets[0].data = (stats.timeline || []).map(([, count]) => count);
  timeChart.update();

  renderList("sources", stats.top_sources || [], "No alerts yet — run python3 nids.py --demo");
  renderList(
    "blocklist",
    (stats.blocked || []).map((ip) => [ip, "blocked"]),
    "Blocklist empty"
  );

  const body = document.getElementById("alerts-body");
  body.innerHTML = alerts
    .map(
      (row) => `<tr>
        <td>${row.timestamp || ""}</td>
        <td><span class="badge ${row.severity || ""}">${row.severity || ""}</span></td>
        <td>${row.sid || ""}</td>
        <td>${row.name || ""}</td>
        <td>${row.src_ip || ""}:${row.src_port || "-"}</td>
        <td>${row.dst_ip || ""}:${row.dst_port || "-"}</td>
        <td>${row.action || "logged"}</td>
      </tr>`
    )
    .join("");
}

refresh();
setInterval(refresh, 3000);
