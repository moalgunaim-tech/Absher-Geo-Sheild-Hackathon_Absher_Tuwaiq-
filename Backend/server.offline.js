// backend/server.offline.js
// سيرفر أوفلاين تجريبي: يشغّل ملفات public + يوفّر Endpoints وهمية للـ AI و Threat Intel

const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

// middlewares
app.use(cors());
app.use(express.json());

// نخلي السيرفر يقدّم ملفات public مباشرة
app.use(express.static(path.join(__dirname, "..", "public")));

// ================== بيانات تجريبية للـ IPs ==================

const MOCK_IP_PROFILES = {
  "185.21.34.90": {
    country: "دولة بعيدة (تجريبية)",
    city: "DataCenter City",
    isp: "Demo Hosting Provider",
    risk: "high",
    vt: {
      malicious: 12,
      suspicious: 3,
      harmless: 5,
      undetected: 10,
      reputation: -50,
    },
    otx: {
      pulse_count: 4,
      top_pulses: [
        "Demo Bruteforce Campaign",
        "Credential Stuffing Test",
      ],
    },
  },
  "156.155.22.40": {
    country: "مصر (تجريبية)",
    city: "Cairo (Demo)",
    isp: "Demo ISP Egypt",
    risk: "high",
    vt: {
      malicious: 8,
      suspicious: 2,
      harmless: 10,
      undetected: 7,
      reputation: -30,
    },
    otx: {
      pulse_count: 3,
      top_pulses: [
        "Phishing Infra Demo",
        "Gov Portal Targeting",
      ],
    },
  },
  "102.44.19.80": {
    country: "الإمارات (تجريبية)",
    city: "Dubai (Demo)",
    isp: "Demo ISP UAE",
    risk: "medium",
    vt: {
      malicious: 2,
      suspicious: 1,
      harmless: 15,
      undetected: 5,
      reputation: 0,
    },
    otx: {
      pulse_count: 1,
      top_pulses: [
        "Suspicious VPN Exit Node (Demo)",
      ],
    },
  },
};

// فحص IPv4 بسيط
function isValidIPv4(ip) {
  if (typeof ip !== "string") return false;
  const trimmed = ip.trim();
  const ipv4Regex =
    /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
  return ipv4Regex.test(trimmed);
}

// بناء ملخص بسيط يعتمد على analytics اللي يرسلها الـ frontend
function buildAnalyticsSummary(analytics) {
  if (!analytics || typeof analytics !== "object") {
    return "لا توجد بيانات إحصائية متوفرة (وضع أوفلاين تجريبي).";
  }

  const {
    totalAttempts = 0,
    low = 0,
    medium = 0,
    high = 0,
    notMeCount = 0,
    securityScore = 10,
    countryStats = {},
  } = analytics;

  const topCountries = Object.entries(countryStats)
    .sort((a, b) => (b[1].total || 0) - (a[1].total || 0))
    .slice(0, 3)
    .map(([country, data]) => {
      const total = data.total || 0;
      const highC = data.high || 0;
      return `${country}: إجمالي ${total} (عالية ${highC})`;
    });

  return `
إجمالي المحاولات: ${totalAttempts}
منخفضة: ${low} / متوسطة: ${medium} / عالية: ${high}
بلاغات "هذا ليس أنا": ${notMeCount}
مستوى الأمان التقريبي: ${securityScore} من 10

أهم الدول:
${topCountries.join("\n") || "لا توجد دول مسجلة بعد."}
`.trim();
}

// ================== 1) حالة الخدمات ==================

app.get("/api/services-status", (req, res) => {
  res.json({
    mode: "offline-demo",
    geo: true,
    vt: true,
    otx: true,
  });
});

// ================== 2) مساعد "ذكاء اصطناعي" أوفلاين ==================

app.post("/api/assistant", (req, res) => {
  const { question, analytics } = req.body || {};

  if (!question) {
    return res.status(400).json({ error: "question is required" });
  }

  const summary = buildAnalyticsSummary(analytics || {});
  const total = analytics?.totalAttempts || 0;
  const high = analytics?.high || 0;
  const medium = analytics?.medium || 0;
  const low = analytics?.low || 0;
  const score = analytics?.securityScore ?? 10;

  let riskComment = "";
  if (score >= 8) {
    riskComment =
      "مستوى الأمان العام جيد، لكن يُنصح بالتركيز على المحاولات القادمة من خارج المملكة والشبكات العامة.";
  } else if (score >= 5) {
    riskComment =
      "مستوى الأمان متوسط، وقد يكون من المناسب توسيع استخدام التحقق الثنائي على الشرائح الحساسة من المستخدمين.";
  } else {
    riskComment =
      "مستوى الأمان منخفض نسبياً، ويوصى بمراجعة السياسة ورفع حساسية النظام أمام المحاولات عالية الخطورة.";
  }

  const answer = `
(وضع تجريبي أوفلاين – بدون نموذج ذكاء اصطناعي حقيقي)

${summary}

تحليل مختصر:
- إجمالي المحاولات: ${total} (منخفضة: ${low} / متوسطة: ${medium} / عالية: ${high})
- مستوى الأمان التقريبي: ${score} من 10
- تعليق عام على المخاطر: ${riskComment}

سؤالك كان:
"${question}"

هذه الأرقام تقدر تستخدمها لتحديد:
- من أي الدول تحتاج تشديد أكبر؟
- هل وقت الهجمات مركّز في ساعات معينة؟
- وهل عدد المحاولات العالية يتجه للزيادة أو النقصان؟
`.trim();

  res.json({ answer });
});

// ================== 3) Threat Intel أوفلاين للـ IP ==================

app.post("/api/ip-intel", (req, res) => {
  const { ip } = req.body || {};
  if (!ip) {
    return res.status(400).json({ error: "ip is required" });
  }

  const ipTrimmed = String(ip).trim();

  if (!isValidIPv4(ipTrimmed)) {
    return res.status(400).json({
      error: "صيغة عنوان الـ IP غير صحيحة (المطلوب IPv4 مثل 185.21.34.90).",
    });
  }

  const profile = MOCK_IP_PROFILES[ipTrimmed] || null;

  const geo = {
    status: "success",
    country: profile?.country || "دولة غير معروفة (ديمو)",
    city: profile?.city || null,
    isp: profile?.isp || "مزود خدمة إنترنت (تجريبي)",
    org: profile?.isp || null,
    as: null,
    proxy: profile?.risk === "high" ? true : false,
    hosting: profile?.risk === "high" ? true : false,
    source: "offline-mock",
  };

  const vtStats = profile?.vt || {
    malicious: 0,
    suspicious: 0,
    harmless: 10,
    undetected: 5,
    reputation: 1,
  };

  const vt = {
    stats: {
      malicious: vtStats.malicious,
      suspicious: vtStats.suspicious,
      harmless: vtStats.harmless,
      undetected: vtStats.undetected,
    },
    reputation: vtStats.reputation,
    last_analysis_date: new Date().toISOString(),
    country: geo.country,
    as_owner: geo.isp,
  };

  const otx = profile?.otx
    ? {
        pulse_count: profile.otx.pulse_count,
        top_pulses: profile.otx.top_pulses,
      }
    : {
        pulse_count: 0,
        top_pulses: [],
        message:
          "لا توجد Pulses حقيقية – هذا مجرد مثال تجريبي بدون اتصال فعلي بـ AlienVault OTX.",
      };

  res.json({
    ip: ipTrimmed,
    geo,
    vt,
    otx,
    fromMock: true,
  });
});

// ================== تشغيل السيرفر ==================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Offline demo server running on http://localhost:${PORT} (serving /public و Endpoints تجريبية)`
  );
});
