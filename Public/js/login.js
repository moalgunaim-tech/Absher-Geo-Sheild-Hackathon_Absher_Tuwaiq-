// public/js/login.js
// تسجيل الدخول التجريبي + ربط المحاولات بـ securityAnalytics في localStorage

const STORAGE_KEY = "securityAnalytics";

const VALID_USER = {
  username: "demo@absher.gov.sa",
  password: "P@ssw0rd!",
};

const usernameInput = document.getElementById("login-username");
const passwordInput = document.getElementById("login-password");
const stateInput = document.getElementById("login-state");
const travelCountryInput = document.getElementById("login-travel-country");
const actualCountryInput = document.getElementById("login-actual-country");
const networkInput = document.getElementById("login-network");
const submitBtn = document.getElementById("login-submit");
const messageEl = document.getElementById("login-message");

// ===== نفس شكل الـ analytics المستخدم في dashboard/stats =====

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
  const riskIndex =
    ((analytics.high || 0) * 3 + (analytics.medium || 0) * 1.5) / total;
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
      high: 0,
    };
  }
  analytics.countryStats[c].total += 1;
  if (attempt.level === "low") analytics.countryStats[c].low += 1;
  else if (attempt.level === "medium")
    analytics.countryStats[c].medium += 1;
  else if (attempt.level === "high") analytics.countryStats[c].high += 1;

  analytics.attemptLog.unshift(attempt);
  if (analytics.attemptLog.length > 500) {
    analytics.attemptLog.pop();
  }

  updateSecurityScore(analytics);
  saveAnalytics(analytics);
}

// ===== منطق تسجيل الدخول =====

function detectDeviceType() {
  // فكرة بسيطة: أول مرة يفتح المتصفح نخزن deviceId → تعتبر "جديد"
  // بعدها تعتبر "معروف"
  let deviceId = localStorage.getItem("demoDeviceId");
  if (!deviceId) {
    try {
      deviceId =
        (window.crypto && crypto.randomUUID && crypto.randomUUID()) ||
        "dev-" + Date.now();
    } catch {
      deviceId = "dev-" + Date.now();
    }
    localStorage.setItem("demoDeviceId", deviceId);
    return "new";
  } else {
    return "known";
  }
}

function mapNetworkFromLogin() {
  const v = networkInput.value;
  if (!v) return "unknown";
  return v;
}

function handleLogin() {
  const username = (usernameInput.value || "").trim();
  const password = passwordInput.value || "";

  const state = stateInput.value;
  const travelCountry = travelCountryInput.value || "";
  const actualCountry = actualCountryInput.value || "";
  const networkType = mapNetworkFromLogin();
  const deviceType = detectDeviceType();

  const success =
    username === VALID_USER.username && password === VALID_USER.password;

  let level = "low";
  let score = 10;
  let shortDecision = "";

  if (success) {
    level = "low";
    score = 10;
    shortDecision = "تسجيل دخول ناجح من صفحة تسجيل الدخول التجريبية.";
  } else {
    level = "medium";
    score = 55;
    shortDecision = "محاولة تسجيل دخول فاشلة بكردنشال خاطئ من صفحة تسجيل الدخول.";
  }

  const attempt = {
    timestamp: new Date().toISOString(),
    state: success ? state : "login-fail",
    travelCountry,
    actualCountry,
    deviceType,
    networkType,
    ip: "", // ممكن تربطها لاحقاً من backend إذا حبيت
    threatTag: "",
    notMe: false,
    level,
    score,
    shortDecision,
    scenario: "login-page",
  };

  logAttemptToAnalytics(attempt);

  // رسالة للمستخدم
  if (success) {
    messageEl.textContent = "تم تسجيل الدخول بنجاح، سيتم تحويلك إلى لوحة الأمان...";
    messageEl.classList.remove("error");
    messageEl.classList.add("success");

    // نخزن المستخدم الحالي بشكل بسيط
    const currentUser = {
      username,
      loginTime: new Date().toISOString(),
    };
    try {
      localStorage.setItem("currentUser", JSON.stringify(currentUser));
    } catch (e) {}

    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 700);
  } else {
    messageEl.textContent =
      "بيانات الدخول غير صحيحة. تم تسجيل هذه المحاولة في الإحصائيات كـ محاولة فاشلة.";
    messageEl.classList.remove("success");
    messageEl.classList.add("error");
    passwordInput.value = "";
    passwordInput.focus();
  }
}

submitBtn.addEventListener("click", handleLogin);

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    handleLogin();
  }
});
