// backend/server.js
// سيرفر "أونلاين" حقيقي:
// - يخدم ملفات public/
// - يتصل بـ OpenAI لأسئلة المساعد
// - يتصل بـ VirusTotal + AlienVault OTX لتحليل IP (إذا توفرت المفاتيح)

// backend/server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// تقديم ملفات الواجهة الأمامية من public
app.use(express.static(path.join(__dirname, "..", "public")));

// مفاتيح الـ APIs من متغيرات البيئة
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const VT_API_KEY = process.env.VT_API_KEY;
const OTX_API_KEY = process.env.OTX_API_KEY;

console.log("=== ENV DEBUG ===");
console.log("OPENAI_API_KEY set?", !!OPENAI_API_KEY);
console.log("VT_API_KEY set?", !!VT_API_KEY);
console.log("OTX_API_KEY set?", !!OTX_API_KEY);
console.log("==================");


// كاش بسيط للـ IPs عشان ما نكرر الطلب كثير
const ipIntelCache = {};

function isValidIPv4(ip) {
  if (typeof ip !== "string") return false;
  const trimmed = ip.trim();
  const ipv4Regex =
    /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
  return ipv4Regex.test(trimmed);
}

// ========== 1) حالة الخدمات (Services Status) ==========

app.get("/api/services-status", (req, res) => {
  res.json({
    mode: OPENAI_API_KEY ? "online" : "online-no-openai",
    geo: true, // ip-api لا تحتاج مفتاح
    vt: !!VT_API_KEY,
    otx: !!OTX_API_KEY,
  });
});

// ========== 2) مساعد الذكاء الاصطناعي عبر OpenAI ==========

app.post("/api/assistant", async (req, res) => {
  const { question, analytics } = req.body || {};

  if (!question) {
    return res.status(400).json({ error: "question is required" });
  }

  if (!OPENAI_API_KEY) {
    return res.status(500).json({
      error: "OPENAI_API_KEY غير موجود في متغيرات البيئة.",
    });
  }

  const payload = {
    model: "gpt-4.1-mini",
    messages: [
      {
        role: "system",
        content:
          "أنت محلل أمن معلومات تقرأ إحصائيات محاولات تسجيل الدخول والتهديدات. أجب دائماً باللغة العربية، وبأسلوب مختصر ومنظم على شكل نقاط.",
      },
      {
        role: "user",
        content:
          `هذه بيانات إحصائية بصيغة JSON قادمة من النظام:\n` +
          `${JSON.stringify(analytics || {}, null, 2)}\n\n` +
          `سؤال المسؤول الأمني:\n${question}\n\n` +
          `رجاءً قدّم تحليلاً مختصراً يركز على: الدول الأخطر، مستوى الهجمات (منخفض/متوسط/عالٍ)، الاتجاه العام، وأهم 3 توصيات عملية.`,
      },
    ],
  };

  try {
    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify(payload),
    });

    if (!openaiRes.ok) {
      const errText = await openaiRes.text();
      console.error("OpenAI error:", openaiRes.status, errText);
      return res.status(500).json({ error: "OpenAI API error" });
    }

    const data = await openaiRes.json();
    const answer =
      data.choices?.[0]?.message?.content ||
      "لم يتم استلام محتوى من نموذج الذكاء الاصطناعي.";

    res.json({ answer });
  } catch (err) {
    console.error("OpenAI fetch error:", err);
    res.status(500).json({ error: "Failed to call OpenAI API" });
  }
});

// ========== 3) Threat Intel للـ IP (Geo + VT + OTX) ==========

app.post("/api/ip-intel", async (req, res) => {
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

  if (ipIntelCache[ipTrimmed]) {
    return res.json(ipIntelCache[ipTrimmed]);
  }

  let geo = {
    status: "unknown",
    country: null,
    city: null,
    isp: null,
    org: null,
    proxy: null,
    hosting: null,
    source: "ip-api",
  };

  let vt = {
    stats: {
      malicious: null,
      suspicious: null,
      harmless: null,
      undetected: null,
    },
    reputation: null,
  };

  let otx = {
    pulse_count: null,
    top_pulses: [],
  };

  // --- Geo عبر ip-api ---
  try {
    const geoRes = await fetch(
      `http://ip-api.com/json/${ipTrimmed}?fields=status,country,city,isp,org,proxy,hosting`
    );
    if (geoRes.ok) {
      const g = await geoRes.json();
      if (g.status === "success") {
        geo = {
          status: g.status,
          country: g.country || null,
          city: g.city || null,
          isp: g.isp || null,
          org: g.org || null,
          proxy: g.proxy ?? null,
          hosting: g.hosting ?? null,
          source: "ip-api",
        };
      } else {
        geo.status = g.status || "fail";
      }
    } else {
      console.error("ip-api HTTP error:", geoRes.status);
      geo.status = "error";
    }
  } catch (e) {
    console.error("ip-api fetch error:", e);
    geo.status = "error";
  }

  // --- VirusTotal ---
  if (VT_API_KEY) {
    try {
      const vtRes = await fetch(
        `https://www.virustotal.com/api/v3/ip_addresses/${ipTrimmed}`,
        {
          headers: {
            "x-apikey": VT_API_KEY,
          },
        }
      );

      if (vtRes.ok) {
        const v = await vtRes.json();
        const attrs = v.data?.attributes || {};
        const st = attrs.last_analysis_stats || {};

        vt = {
          stats: {
            malicious: st.malicious ?? null,
            suspicious: st.suspicious ?? null,
            harmless: st.harmless ?? null,
            undetected: st.undetected ?? null,
          },
          reputation: attrs.reputation ?? null,
          last_analysis_date: attrs.last_analysis_date
            ? new Date(attrs.last_analysis_date * 1000).toISOString()
            : null,
          country: attrs.country || geo.country || null,
          as_owner: attrs.as_owner || geo.isp || null,
        };
      } else {
        console.error("VT HTTP error:", vtRes.status);
      }
    } catch (e) {
      console.error("VT fetch error:", e);
    }
  } else {
    vt.message = "VT_API_KEY غير متوفر – يمكن تفعيله لاحقاً.";
  }

  // --- AlienVault OTX ---
  if (OTX_API_KEY) {
    try {
      const otxRes = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/IPv4/${ipTrimmed}/general`,
        {
          headers: {
            "X-OTX-API-KEY": OTX_API_KEY,
          },
        }
      );

      if (otxRes.ok) {
        const o = await otxRes.json();
        const pulseInfo = o.pulse_info || {};
        const pulses = pulseInfo.pulses || [];

        otx = {
          pulse_count: pulseInfo.count ?? pulses.length,
          top_pulses: pulses.slice(0, 5).map((p) => p.name),
        };
      } else {
        console.error("OTX HTTP error:", otxRes.status);
      }
    } catch (e) {
      console.error("OTX fetch error:", e);
    }
  } else {
    otx.message = "OTX_API_KEY غير متوفر – يمكن تفعيله لاحقاً.";
  }

  const result = {
    ip: ipTrimmed,
    geo,
    vt,
    otx,
    fromMock: false,
  };

  ipIntelCache[ipTrimmed] = result;
  res.json(result);
});

// ========== تشغيل السيرفر ==========

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(
    `Online security server running on http://localhost:${PORT} (OpenAI + Threat Intel)`
  );
});
