const STORAGE_KEY = "securityAnalytics";
const RISK_WEIGHTS_KEY = "riskWeights";

const DEFAULT_WEIGHTS = {
  travelMismatch: 25,
  newDevice: 20,
  networkRisk: 15,
  threatIntel: 30,
  notMe: 40
};

const stateInput = document.getElementById("input-state");
const travelCountryInput = document.getElementById("input-travel-country");
const actualCountryInput = document.getElementById("input-actual-country");
const deviceInput = document.getElementById("input-device");
const networkInput = document.getElementById("input-network");
const ipInput = document.getElementById("input-ip");
const threatInput = document.getElementById("input-threat");
const notMeInput = document.getElementById("input-not-me");

const btnEvaluate = document.getElementById("btn-evaluate");

const riskLevelBadge = document.getElementById("risk-level-badge");
const riskScoreEl = document.getElementById("risk-score");
const decisionText = document.getElementById("decision-text");
const riskReasonsList = document.getElementById("risk-reasons-list");
const userMessageEl = document.getElementById("user-message");

const mfaLow = document.getElementById("mfa-low");
const mfaMedium = document.getElementById("mfa-medium");
const mfaHigh = document.getElementById("mfa-high");

const btnModeUser = document.getElementById("btn-mode-user");
const btnModeSoc = document.getElementById("btn-mode-soc");

const sliders = {
  travelMismatch: document.getElementById("w-travel-mismatch"),
  newDevice: document.getElementById("w-new-device"),
  networkRisk: document.getElementById("w-network-risk"),
  threatIntel: document.getElementById("w-threat-intel"),
  notMe: document.getElementById("w-not-me")
};

const sliderLabels = {
  travelMismatch: document.getElementById("w-travel-mismatch-val"),
  newDevice: document.getElementById("w-new-device-val"),
  networkRisk: document.getElementById("w-network-risk-val"),
  threatIntel: document.getElementById("w-threat-intel-val"),
  notMe: document.getElementById("w-not-me-val")
};

function loadRiskWeights() {
  try {
    const raw = localStorage.getItem(RISK_WEIGHTS_KEY);
    if (!raw) return { ...DEFAULT_WEIGHTS };
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_WEIGHTS, ...parsed };
  } catch (e) {
    return { ...DEFAULT_WEIGHTS };
  }
}

function saveRiskWeights(weights) {
  try {
    localStorage.setItem(RISK_WEIGHTS_KEY, JSON.stringify(weights));
  } catch (e) {}
}

function initSliders() {
  const weights = loadRiskWeights();

  sliders.travelMismatch.value = weights.travelMismatch;
  sliders.newDevice.value = weights.newDevice;
  sliders.networkRisk.value = weights.networkRisk;
  sliders.threatIntel.value = weights.threatIntel;
  sliders.notMe.value = weights.notMe;

  sliderLabels.travelMismatch.textContent = weights.travelMismatch;
  sliderLabels.newDevice.textContent = weights.newDevice;
  sliderLabels.networkRisk.textContent = weights.networkRisk;
  sliderLabels.threatIntel.textContent = weights.threatIntel;
  sliderLabels.notMe.textContent = weights.notMe;

  Object.keys(sliders).forEach((key) => {
    sliders[key].addEventListener("input", () => {
      const val = parseInt(sliders[key].value, 10) || 0;
      sliderLabels[key].textContent = val;
      const current = loadRiskWeights();
      current[key] = val;
      saveRiskWeights(current);
    });
  });
}

function getCurrentWeights() {
  return loadRiskWeights();
}

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
        lastUpdated: null
      };
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") throw new Error();
    parsed.totalAttempts = parsed.totalAttempts || 0;
    parsed.low = parsed.low || 0;
    parsed.medium = parsed.medium || 0;
    parsed.high = parsed.high || 0;
    parsed.notMeCount = parsed.notMeCount || 0;
    parsed.securityScore = typeof parsed.securityScore === "number" ? parsed.securityScore : 10;
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
      lastUpdated: null
    };
  }
}

function saveAnalytics(analytics) {
  analytics.lastUpdated = new Date().toISOString();
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(analytics));
  } catch (e) {}
}

function updateSecurityScore(analytics) {
  const total = analytics.totalAttempts || 0;
  if (!total) {
    analytics.securityScore = 10;
    return;
  }
  const riskIndex = ((analytics.high || 0) * 3 + (analytics.medium || 0) * 1.5) / total;
  const score = 10 - riskIndex;
  analytics.securityScore = Math.max(1, Math.min(10, score));
}

function logAttemptToAnalytics(attempt) {
  const analytics = loadAnalytics();
  analytics.totalAttempts += 1;
  if (attempt.level === "low") analytics.low += 1;
  else if (attempt.level === "medium") analytics.medium += 1;
  else if (attempt.level === "high") analytics.high += 1;

  if (attempt.notMe) {
    analytics.notMeCount += 1;
  }

  const c = attempt.actualCountry || "غير معروف";
  if (!analytics.countryStats[c]) {
    analytics.countryStats[c] = {
      total: 0,
      low: 0,
      medium: 0,
      high: 0
    };
  }
  analytics.countryStats[c].total += 1;
  if (attempt.level === "low") analytics.countryStats[c].low += 1;
  else if (attempt.level === "medium") analytics.countryStats[c].medium += 1;
  else if (attempt.level === "high") analytics.countryStats[c].high += 1;

  analytics.attemptLog.unshift(attempt);
  if (analytics.attemptLog.length > 500) {
    analytics.attemptLog.pop();
  }

  updateSecurityScore(analytics);
  saveAnalytics(analytics);
}

function setMode(mode) {
  if (mode === "user") {
    document.body.classList.remove("soc-mode");
    document.body.classList.add("user-mode");
    btnModeUser.classList.add("mode-btn-active");
    btnModeSoc.classList.remove("mode-btn-active");
  } else {
    document.body.classList.remove("user-mode");
    document.body.classList.add("soc-mode");
    btnModeSoc.classList.add("mode-btn-active");
    btnModeUser.classList.remove("mode-btn-active");
  }
}

btnModeUser.addEventListener("click", () => setMode("user"));
btnModeSoc.addEventListener("click", () => setMode("soc"));

function applyScenario(type) {
  if (type === "safe") {
    stateInput.value = "inside";
    travelCountryInput.value = "";
    actualCountryInput.value = "السعودية";
    deviceInput.value = "known";
    networkInput.value = "home";
    ipInput.value = "51.36.22.10";
    threatInput.value = "";
    notMeInput.checked = false;
  } else if (type === "medium") {
    stateInput.value = "traveler";
    travelCountryInput.value = "الإمارات";
    actualCountryInput.value = "الإمارات";
    deviceInput.value = "new";
    networkInput.value = "public";
    ipInput.value = "102.44.19.80";
    threatInput.value = "";
    notMeInput.checked = false;
  } else if (type === "high") {
    stateInput.value = "inside";
    travelCountryInput.value = "";
    actualCountryInput.value = "دولة بعيدة";
    deviceInput.value = "new";
    networkInput.value = "vpn";
    ipInput.value = "185.21.34.90";
    threatInput.value = "Bruteforce_Global";
    notMeInput.checked = false;
  } else if (type === "egypt") {
    stateInput.value = "inside";
    travelCountryInput.value = "";
    actualCountryInput.value = "مصر";
    deviceInput.value = "unknown";
    networkInput.value = "public";
    ipInput.value = "156.155.22.40";
    threatInput.value = "Phishing_Campaign";
    notMeInput.checked = false;
  }
}

document.getElementById("scenario-safe").addEventListener("click", () => {
  applyScenario("safe");
});
document.getElementById("scenario-medium").addEventListener("click", () => {
  applyScenario("medium");
});
document.getElementById("scenario-high").addEventListener("click", () => {
  applyScenario("high");
});
document.getElementById("scenario-egypt").addEventListener("click", () => {
  applyScenario("egypt");
});

function evaluateRisk() {
  const state = stateInput.value;
  const travelCountry = travelCountryInput.value || "";
  const actualCountry = actualCountryInput.value || "";
  const deviceType = deviceInput.value;
  const networkType = networkInput.value;
  const ip = (ipInput.value || "").trim();
  const threatTag = threatInput ? (threatInput.value || "") : "";
  const notMe = !!notMeInput.checked;

  const weights = getCurrentWeights();

  let score = 0;
  const reasons = [];

  if (state === "login-fail") {
    score += 30;
    reasons.push("محاولة تسجيل دخول بكردنشال خاطئ.");
  }

  let expectedCountry = "";
  if (state === "inside") {
    expectedCountry = "السعودية";
  } else if (state === "traveler" && travelCountry) {
    expectedCountry = travelCountry;
  }

  if (actualCountry && expectedCountry && actualCountry !== expectedCountry) {
    score += weights.travelMismatch;
    reasons.push("دولة المحاولة مختلفة عن حالة أبشر (داخل/مسافر).");
  }

  if (deviceType === "new") {
    score += weights.newDevice;
    reasons.push("المحاولة من جهاز جديد على الحساب.");
  } else if (deviceType === "unknown") {
    score += Math.round(weights.newDevice * 0.7);
    reasons.push("المحاولة من جهاز غير موثوق / بصمة غير معروفة.");
  }

  if (networkType === "public" || networkType === "vpn") {
    score += weights.networkRisk;
    reasons.push("المحاولة من شبكة غير موثوقة (عامة أو VPN).");
  } else if (networkType === "unknown") {
    score += Math.round(weights.networkRisk * 0.5);
    reasons.push("نوع الشبكة غير معروف، ما يرفع درجة الشك قليلاً.");
  }

  if (threatTag) {
    score += weights.threatIntel;
    reasons.push("عنوان الـ IP مرتبط بوسم Threat Intel (حملة أو مصدر معروف بالهجمات).");
  }

  if (notMe) {
    score += weights.notMe;
    reasons.push('المستخدم أبلغ أن هذه المحاولة "ليست منه".');
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  let level = "low";
  if (notMe || score >= 80) {
    level = "high";
  } else if (score >= 35) {
    level = "medium";
  }

  let levelText = "منخفضة";
  let badgeClass = "badge-low";
  if (level === "medium") {
    levelText = "متوسطة";
    badgeClass = "badge-medium";
  } else if (level === "high") {
    levelText = "عالية";
    badgeClass = "badge-high";
  }

  riskLevelBadge.classList.remove("badge-low", "badge-medium", "badge-high");
  riskLevelBadge.classList.add(badgeClass);
  riskLevelBadge.innerHTML = `مستوى الخطورة: <strong>${levelText}</strong>`;

  riskScoreEl.textContent = Math.round(score).toString();

  let decision = "";
  let userText = "";

  if (level === "low") {
    decision = "قرار النظام: السماح بالدخول مباشرة بدون خطوة إضافية.";
    userText = "تم التحقق من محاولتك، وتم السماح بالدخول بشكل طبيعي.";
  } else if (level === "medium") {
    decision = "قرار النظام: يتطلب تحقق إضافي (رمز تحقق لمرة واحدة).";
    userText = "من باب الحماية، نحتاج منك تأكيد إضافي (رمز تحقق) قبل إكمال الدخول.";
  } else {
    decision = "قرار النظام: حظر المحاولة فوراً، مع إشعار المستخدم وفريق الأمن.";
    userText = "تم إيقاف هذه المحاولة كإجراء أمني، وقد يتم التواصل معك للتأكد من سلامة حسابك.";
  }

  if (notMe) {
    decision += " (تم رفع المستوى بسبب بلاغ المستخدم بأن هذه المحاولة ليست منه).";
  }

  decisionText.textContent = decision;
  if (userMessageEl) userMessageEl.textContent = userText;

  if (riskReasonsList) {
    riskReasonsList.innerHTML = "";
    if (!reasons.length) {
      const li = document.createElement("li");
      li.textContent = "لم يتم تسجيل أسباب إضافية، المحاولة تبدو عادية وفق المعايير الحالية.";
      riskReasonsList.appendChild(li);
    } else {
      reasons.forEach((r) => {
        const li = document.createElement("li");
        li.textContent = r;
        riskReasonsList.appendChild(li);
      });
    }
  }

  mfaLow.style.display = "none";
  mfaMedium.style.display = "none";
  mfaHigh.style.display = "none";

  if (level === "low") {
    mfaLow.style.display = "block";
  } else if (level === "medium") {
    mfaMedium.style.display = "block";
  } else if (level === "high") {
    mfaHigh.style.display = "block";
  }

  const attempt = {
    timestamp: new Date().toISOString(),
    state,
    travelCountry,
    actualCountry,
    deviceType,
    networkType,
    ip: ip || "",
    threatTag: threatTag || "",
    notMe,
    level,
    score: Math.round(score),
    shortDecision: decision,
    scenario: null
  };

  logAttemptToAnalytics(attempt);
}

btnEvaluate.addEventListener("click", evaluateRisk);

initSliders();
setMode("soc");
