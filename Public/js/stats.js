// public/js/stats.js
const STORAGE_KEY = "securityAnalytics";

const statTotalEl = document.getElementById("stat-total");
const statLowEl = document.getElementById("stat-low");
const statMediumEl = document.getElementById("stat-medium");
const statHighEl = document.getElementById("stat-high");
const statNotMeEl = document.getElementById("stat-not-me");
const statScoreEl = document.getElementById("stat-score");
const statDaysNoHighEl = document.getElementById("stat-days-no-high");
const statLastHighTextEl = document.getElementById("stat-last-high-text");

const bannerHigh = document.getElementById("banner-high");
const bannerHighText = document.getElementById("banner-high-text");

const servicesModeEl = document.getElementById("services-mode");
const servicesGeoEl = document.getElementById("services-geo");
const servicesVtEl = document.getElementById("services-vt");
const servicesOtxEl = document.getElementById("services-otx");

const countryGridEl = document.getElementById("country-grid");
const countryEmptyEl = document.getElementById("country-empty");

const hourBarsEl = document.getElementById("hour-bars");
const hoursEmptyEl = document.getElementById("hours-empty");

const filterRiskEl = document.getElementById("filter-risk");
const filterCountryEl = document.getElementById("filter-country");
const filterNotMeOnlyEl = document.getElementById("filter-not-me-only");
const attemptsBodyEl = document.getElementById("attempts-body");

const threatTotalEl = document.getElementById("threat-total");
const threatTableBodyEl = document.getElementById("threat-table-body");
const threatEmptyEl = document.getElementById("threat-empty");

const aiQuestionEl = document.getElementById("ai-question");
const aiAskBtn = document.getElementById("btn-ai-ask");
const aiStatusEl = document.getElementById("ai-status");
const aiAnswerEl = document.getElementById("ai-answer");

const ipModalEl = document.getElementById("ip-modal");
const ipModalCloseBtn = document.getElementById("ip-modal-close");
const ipModalIpEl = document.getElementById("ip-modal-ip");
const ipModalStatusEl = document.getElementById("ip-modal-status");
const ipModalContentEl = document.getElementById("ip-modal-content");

let analytics = null;
const ipIntelCache = {};

// ========== مساعد دوال عامة ==========

function loadAnalytics() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        totalAttempts: 0,
        low: 0,
        medium: 0,
        high: 0,
        notMeCount: 0,
        securityScore: 10,
        countryStats: {},
        attemptLog: [],
        lastUpdated: null,
      };
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") throw new Error();
    parsed.totalAttempts = parsed.totalAttempts || 0;
    parsed.low = parsed.low || 0;
    parsed.medium = parsed.medium || 0;
    parsed.high = parsed.high || 0;
    parsed.notMeCount = parsed.notMeCount || 0;
    parsed.securityScore =
      typeof parsed.securityScore === "number" ? parsed.securityScore : 10;
    parsed.countryStats = parsed.countryStats || {};
    parsed.attemptLog = parsed.attemptLog || [];
    return parsed;
  } catch (e) {
    return {
      totalAttempts: 0,
      low: 0,
      medium: 0,
      high: 0,
      notMeCount: 0,
      securityScore: 10,
      countryStats: {},
      attemptLog: [],
      lastUpdated: null,
    };
  }
}

function setStatusPill(el, ok) {
  if (!el) return;
  el.classList.remove("status-ok", "status-bad");
  if (ok === null) {
    el.textContent = "غير معروف";
    return;
  }
  if (ok) {
    el.classList.add("status-ok");
    el.textContent = "متصل";
  } else {
    el.classList.add("status-bad");
    el.textContent = "غير متاح";
  }
}

function formatRelativeTime(fromDate, toDate) {
  const diffMs = toDate - fromDate;
  if (diffMs < 0) return "قبل قليل";

  const minutes = Math.floor(diffMs / 60000);
  const hours = Math.floor(diffMs / 3600000);
  const days = Math.floor(diffMs / 86400000);

  if (minutes < 1) return "منذ ثوانٍ";
  if (minutes < 60) return `منذ ${minutes} دقيقة`;
  if (hours < 24) return `منذ ${hours} ساعة`;
  return `منذ ${days} يوم`;
}

function formatDateTime(ts) {
  if (!ts) return "غير معروف";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "غير معروف";
  try {
    return d.toLocaleString("ar-SA");
  } catch {
    return d.toLocaleString();
  }
}

function mapLevelToText(level) {
  if (level === "high") return "عالية";
  if (level === "medium") return "متوسطة";
  return "منخفضة";
}

function mapDeviceToText(deviceType) {
  if (deviceType === "known") return "جهاز معروف";
  if (deviceType === "new") return "جديد";
  if (deviceType === "unknown") return "غير معروف";
  return "غير محدد";
}

function mapNetworkToText(networkType) {
  if (networkType === "home") return "منزلية";
  if (networkType === "office") return "عمل / جهة";
  if (networkType === "public") return "شبكة عامة";
  if (networkType === "vpn") return "VPN / Proxy";
  if (networkType === "unknown") return "غير معروف";
  return "غير محدد";
}

// ========== 1) ملخص أعلى الصفحة ==========

function renderSummary() {
  const a = analytics;
  statTotalEl.textContent = a.totalAttempts || 0;
  statLowEl.textContent = a.low || 0;
  statMediumEl.textContent = a.medium || 0;
  statHighEl.textContent = a.high || 0;
  statNotMeEl.textContent = a.notMeCount || 0;
  statScoreEl.textContent = typeof a.securityScore === "number" ? a.securityScore : 10;

  const now = new Date();
  const lastHighAttempt = (a.attemptLog || []).find((att) => att.level === "high");

  if (!lastHighAttempt) {
    statDaysNoHighEl.textContent = "—";
    statLastHighTextEl.textContent = "لا يوجد";
    bannerHigh.classList.add("hidden");
    return;
  }

  const lastDate = new Date(lastHighAttempt.timestamp);
  if (isNaN(lastDate.getTime())) {
    statDaysNoHighEl.textContent = "—";
    statLastHighTextEl.textContent = "غير معروف";
    bannerHigh.classList.add("hidden");
    return;
  }

  const diffMs = now - lastDate;
  const days = Math.floor(diffMs / 86400000);
  statDaysNoHighEl.textContent = days.toString();
  statLastHighTextEl.textContent = formatDateTime(lastHighAttempt.timestamp);

  // نظهر البانر لو الهجمة خلال آخر 3 ساعات مثلاً
  if (diffMs <= 3 * 3600000) {
    const rel = formatRelativeTime(lastDate, now);
    const country = lastHighAttempt.actualCountry || "غير معروفة";
    bannerHighText.textContent = `تم رصد محاولة عالية الخطورة ${rel} من دولة ${country}.`;
    bannerHigh.classList.remove("hidden");
  } else {
    bannerHigh.classList.add("hidden");
  }
}

// ========== 2) حالة الخدمات (Services) ==========

async function refreshServicesStatus() {
  try {
    const res = await fetch("/api/services-status");
    if (!res.ok) throw new Error("HTTP error");
    const data = await res.json();
    servicesModeEl.textContent = data.mode || "غير معروف";
    setStatusPill(servicesGeoEl, !!data.geo);
    setStatusPill(servicesVtEl, !!data.vt);
    setStatusPill(servicesOtxEl, !!data.otx);
  } catch (e) {
    servicesModeEl.textContent = "غير متصل";
    setStatusPill(servicesGeoEl, false);
    setStatusPill(servicesVtEl, false);
    setStatusPill(servicesOtxEl, false);
  }
}

// ========== 3) الدول (خريطة منطقية) ==========

function renderCountries() {
  const stats = analytics.countryStats || {};
  const entries = Object.entries(stats);
  countryGridEl.innerHTML = "";

  if (!entries.length) {
    countryEmptyEl.style.display = "block";
    return;
  }
  countryEmptyEl.style.display = "none";

  const totals = entries.map(([_, v]) => v.total || 0);
  const maxTotal = Math.max(...totals, 0);

  entries
    .sort((a, b) => (b[1].total || 0) - (a[1].total || 0))
    .forEach(([country, data]) => {
      const total = data.total || 0;
      const high = data.high || 0;
      const intensity =
        maxTotal > 0 ? 0.25 + 0.75 * (total / maxTotal) : 0.3;

      const card = document.createElement("div");
      card.className = "country-card";
      card.style.setProperty("--intensity", intensity.toString());
      card.innerHTML = `
        <div class="country-name">${country}</div>
        <div class="country-metrics">إجمالي: ${total} | عالية: ${high}</div>
      `;
      countryGridEl.appendChild(card);
    });
}

// ========== 4) توزيع الساعات ==========

function renderHours() {
  const attempts = analytics.attemptLog || [];
  hourBarsEl.innerHTML = "";

  if (!attempts.length) {
    hoursEmptyEl.style.display = "block";
    return;
  }
  hoursEmptyEl.style.display = "none";

  const counts = new Array(24).fill(0);
  attempts.forEach((att) => {
    const d = new Date(att.timestamp);
    if (!isNaN(d.getTime())) {
      const h = d.getHours();
      counts[h] += 1;
    }
  });

  const max = Math.max(...counts, 0) || 1;

  for (let h = 0; h < 24; h++) {
    const bar = document.createElement("div");
    bar.className = "hour-bar";

    const inner = document.createElement("div");
    inner.className = "hour-bar-inner";

    const heightPercent = (counts[h] / max) * 100;
    inner.style.height = `${Math.max(3, heightPercent)}%`;

    const label = document.createElement("div");
    label.className = "hour-bar-label";
    label.textContent = h.toString();

    bar.appendChild(inner);
    bar.appendChild(label);
    hourBarsEl.appendChild(bar);
  }
}

// ========== 5) Threat Intel Widget ==========

function renderThreatIntel() {
  const attempts = analytics.attemptLog || [];
  const ipMap = {};
  let totalThreatRelated = 0;

  attempts.forEach((att) => {
    const hasThreatTag = !!att.threatTag;
    const ip = (att.ip || "").trim();
    if (hasThreatTag || ip) {
      totalThreatRelated += 1;
    }
    if (!ip) return;

    if (!ipMap[ip]) {
      ipMap[ip] = {
        count: 0,
        lastThreat: att.threatTag || "",
        maxLevel: att.level || "low",
      };
    }
    ipMap[ip].count += 1;
    if (att.threatTag) {
      ipMap[ip].lastThreat = att.threatTag;
    }
    const order = { low: 1, medium: 2, high: 3 };
    const current = ipMap[ip].maxLevel || "low";
    if ((order[att.level] || 1) > (order[current] || 1)) {
      ipMap[ip].maxLevel = att.level;
    }
  });

  threatTotalEl.textContent = totalThreatRelated;

  const entries = Object.entries(ipMap);
  threatTableBodyEl.innerHTML = "";

  if (!entries.length) {
    threatEmptyEl.style.display = "block";
    return;
  }
  threatEmptyEl.style.display = "none";

  entries
    .sort((a, b) => b[1].count - a[1].count)
    .forEach(([ip, data]) => {
      const tr = document.createElement("tr");

      const levelText = mapLevelToText(data.maxLevel);
      let badgeClass = "badge-low";
      if (data.maxLevel === "medium") badgeClass = "badge-medium";
      else if (data.maxLevel === "high") badgeClass = "badge-high";

      tr.innerHTML = `
        <td>${ip}</td>
        <td>${data.lastThreat || "—"}</td>
        <td>${data.count}</td>
        <td><span class="${badgeClass}">${levelText}</span></td>
        <td>
          <button class="btn-small btn-ip-intel" data-ip="${ip}">
            تحليل IP
          </button>
        </td>
      `;
      threatTableBodyEl.appendChild(tr);
    });
}

// ========== 6) الفلاتر + جدول المحاولات ==========

function populateCountryFilter() {
  const stats = analytics.countryStats || {};
  const entries = Object.entries(stats).sort(
    (a, b) => (b[1].total || 0) - (a[1].total || 0)
  );

  filterCountryEl.innerHTML = "";
  const optAll = document.createElement("option");
  optAll.value = "";
  optAll.textContent = "كل الدول";
  filterCountryEl.appendChild(optAll);

  entries.forEach(([country]) => {
    const opt = document.createElement("option");
    opt.value = country;
    opt.textContent = country;
    filterCountryEl.appendChild(opt);
  });
}

function renderAttempts() {
  const attempts = analytics.attemptLog || [];
  const riskFilter = filterRiskEl.value;
  const countryFilter = filterCountryEl.value;
  const onlyNotMe = !!filterNotMeOnlyEl.checked;

  attemptsBodyEl.innerHTML = "";

  const filtered = attempts.filter((att) => {
    if (riskFilter && att.level !== riskFilter) return false;

    const c = att.actualCountry || "غير معروف";
    if (countryFilter && c !== countryFilter) return false;

    if (onlyNotMe && !att.notMe) return false;

    return true;
  });

  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.textContent = "لا توجد محاولات مطابقة للفلاتر الحالية.";
    td.style.textAlign = "center";
    tr.appendChild(td);
    attemptsBodyEl.appendChild(tr);
    return;
  }

  filtered.slice(0, 200).forEach((att) => {
    const tr = document.createElement("tr");

    const levelText = mapLevelToText(att.level);
    let badgeClass = "badge-low";
    if (att.level === "medium") badgeClass = "badge-medium";
    else if (att.level === "high") badgeClass = "badge-high";

    const ip = (att.ip || "").trim();
    const notMeText = att.notMe ? "بلاغ" : "—";

    tr.innerHTML = `
      <td>${formatDateTime(att.timestamp)}</td>
      <td>${att.actualCountry || "غير معروف"}</td>
      <td><span class="${badgeClass}">${levelText}</span></td>
      <td>${mapDeviceToText(att.deviceType)}</td>
      <td>${mapNetworkToText(att.networkType)}</td>
      <td>
        ${
          ip
            ? `${ip} <button class="btn-small btn-ip-intel" data-ip="${ip}">تحليل</button>`
            : "—"
        }
      </td>
      <td>${notMeText}</td>
    `;
    attemptsBodyEl.appendChild(tr);
  });
}

function setupFilters() {
  filterRiskEl.addEventListener("change", renderAttempts);
  filterCountryEl.addEventListener("change", renderAttempts);
  filterNotMeOnlyEl.addEventListener("change", renderAttempts);
}

// ========== 7) مساعد الذكاء الاصطناعي (واجهة) ==========

async function callAssistant(question) {
  const body = {
    question,
    analytics: loadAnalytics(), // نقرأ آخر نسخة من الـ analytics
  };

  const res = await fetch("/api/assistant", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) throw new Error("assistant HTTP error");
  const data = await res.json();
  return data.answer || "لم يصل رد من المساعد.";
}

function setupAssistant() {
  aiAskBtn.addEventListener("click", async () => {
    const q = (aiQuestionEl.value || "").trim();
    if (!q) {
      aiStatusEl.textContent = "اكتب سؤالاً أولاً.";
      return;
    }

    aiStatusEl.textContent = "جارِ إرسال السؤال...";
    aiAskBtn.disabled = true;

    try {
      const answer = await callAssistant(q);
      aiAnswerEl.textContent = answer;
      aiStatusEl.textContent = "تم استلام الإجابة.";
    } catch (e) {
      aiAnswerEl.textContent =
        "تعذر الاتصال بخادم المساعد. يمكن استخدام هذا المكوّن كتوضيح لنقطة دمج الذكاء الاصطناعي.";
      aiStatusEl.textContent = "حدث خطأ في الاتصال.";
    } finally {
      aiAskBtn.disabled = false;
    }
  });
}

// ========== 8) مودال IP Threat Intel ==========

function closeIpModal() {
  ipModalEl.classList.add("hidden");
}

function openIpModal(ip) {
  ipModalEl.classList.remove("hidden");
  ipModalIpEl.textContent = ip;
  ipModalStatusEl.textContent = "جارِ جلب بيانات Threat Intel لهذا العنوان...";
  ipModalContentEl.textContent = "";
  loadIpIntel(ip);
}

async function fetchIpIntel(ip) {
  if (ipIntelCache[ip]) return ipIntelCache[ip];

  const res = await fetch("/api/ip-intel", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ip }),
  });

  if (!res.ok) {
    throw new Error("ip-intel HTTP error");
  }
  const data = await res.json();
  ipIntelCache[ip] = data;
  return data;
}

function buildIpIntelHtml(data) {
  const geo = data.geo || {};
  const vt = data.vt || {};
  const stats = vt.stats || {};
  const otx = data.otx || {};

  const pulses = otx.top_pulses || [];

  return `
    <div class="ip-section">
      <div class="modal-section-title">الموقع التقريبي (GeoIP):</div>
      <div>الدولة: ${geo.country || "غير معروفة"}</div>
      <div>المدينة: ${geo.city || "غير معروفة"}</div>
      <div>مزود الخدمة: ${geo.isp || "غير متوفر"}</div>
    </div>

    <div class="ip-section">
      <div class="modal-section-title">ملخص VirusTotal (تجريبي):</div>
      <div>Malicious: ${stats.malicious != null ? stats.malicious : "?"}</div>
      <div>Suspicious: ${stats.suspicious != null ? stats.suspicious : "?"}</div>
      <div>Harmless: ${stats.harmless != null ? stats.harmless : "?"}</div>
      <div>Undetected: ${stats.undetected != null ? stats.undetected : "?"}</div>
      <div>السمعة: ${vt.reputation != null ? vt.reputation : "غير متوفر"}</div>
    </div>

    <div class="ip-section">
      <div class="modal-section-title">AlienVault OTX (تجريبي):</div>
      <div>عدد الـ Pulses: ${otx.pulse_count != null ? otx.pulse_count : 0}</div>
      ${
        pulses.length
          ? `<div>أهم الحملات المرتبطة:</div>
             <ul>${pulses
               .map((p) => `<li>${p}</li>`)
               .join("")}</ul>`
          : "<div>لا توجد حملات معروفة لهذا العنوان في البيانات التجريبية.</div>"
      }
    </div>
  `;
}

async function loadIpIntel(ip) {
  try {
    const data = await fetchIpIntel(ip);
    ipModalStatusEl.textContent = "";
    ipModalContentEl.innerHTML = buildIpIntelHtml(data);
  } catch (e) {
    ipModalStatusEl.textContent =
      "تعذر جلب بيانات Threat Intel لهذا العنوان. في وضع الأوفلاين يمكن الاكتفاء بهذه الشاشة كتوضيح للفكرة.";
    ipModalContentEl.textContent = "";
  }
}

function setupIpModal() {
  ipModalCloseBtn.addEventListener("click", closeIpModal);
  ipModalEl.addEventListener("click", (e) => {
    if (e.target === ipModalEl) {
      closeIpModal();
    }
  });

  // Event delegation للأزرار اللي فيها class="btn-ip-intel"
  attemptsBodyEl.addEventListener("click", (e) => {
    const target = e.target;
    if (target && target.classList.contains("btn-ip-intel")) {
      const ip = target.getAttribute("data-ip");
      if (ip) openIpModal(ip);
    }
  });

  threatTableBodyEl.addEventListener("click", (e) => {
    const target = e.target;
    if (target && target.classList.contains("btn-ip-intel")) {
      const ip = target.getAttribute("data-ip");
      if (ip) openIpModal(ip);
    }
  });
}

// ========== 9) تهيئة الصفحة ==========

function initStatsPage() {
  analytics = loadAnalytics();

  renderSummary();
  renderCountries();
  renderHours();
  renderThreatIntel();
  populateCountryFilter();
  renderAttempts();
  setupFilters();
  setupAssistant();
  setupIpModal();
  refreshServicesStatus();
}

document.addEventListener("DOMContentLoaded", initStatsPage);
