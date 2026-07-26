const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

dotenv.config();
const app = express();

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false // Allows loading Google Fonts, CDN scripts (html2pdf, marked), and inline scripts
}));

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// Rate Limiting: max 10 requests per hour per IP
const analyzeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 10, // 10 requests per hour
  message: { error: 'Rate limit exceeded: Maximum 10 requests per hour per IP. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Helper for sanitizing user inputs
function sanitize(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[^\w\s\-\.,\/\(\)\$\+\%\:\;]/gi, '')
    .trim()
    .slice(0, 300);
}

// Robust JSON extraction & cleanup helper
function extractAndParseJSON(rawText) {
  if (!rawText || typeof rawText !== 'string') return null;
  
  // 1. Remove markdown code fences
  let clean = rawText.replace(/```json/gi, '').replace(/```/g, '').trim();

  // 2. Extract first '{' to last '}'
  const start = clean.indexOf('{');
  const end = clean.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    clean = clean.substring(start, end + 1);
  }

  // 3. Try standard parse
  try {
    return JSON.parse(clean);
  } catch (err1) {
    console.warn('Initial JSON parse failed, applying regex cleanup...');
    try {
      // Clean trailing commas before closing brackets/braces and strip unescaped control chars
      const sanitized = clean
        .replace(/,\s*([\]}])/g, '$1')
        .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ");
      return JSON.parse(sanitized);
    } catch (err2) {
      console.error('Failed to parse clean JSON:', err2.message);
      return null;
    }
  }
}

// Request Logger: appends request evidence to logs.txt
function logRequest({ nationality, profession, budget, recommendedCountries }) {
  const timestamp = new Date().toISOString();
  const logLine = `[${timestamp}] Nationality: ${nationality} | Profession: ${profession} | Budget: $${budget} | Recommended: ${recommendedCountries || 'N/A'}\n`;
  fs.appendFile(path.join(__dirname, 'logs.txt'), logLine, (err) => {
    if (err) console.error('Failed to write to logs.txt:', err.message);
  });
}

app.post('/analyze', analyzeLimiter, async (req, res) => {
  const rawBody = req.body || {};
  const nationality = sanitize(rawBody.nationality);
  const age = sanitize(rawBody.age);
  const profession = sanitize(rawBody.profession);
  const budget = sanitize(String(rawBody.budget || ''));
  const languages = sanitize(rawBody.languages);
  const reason = sanitize(rawBody.reason);
  const priorities = sanitize(rawBody.priorities);
  const family = sanitize(rawBody.family);
  const govtype = sanitize(rawBody.govtype);
  const education = sanitize(rawBody.education);
  const experience = sanitize(rawBody.experience);
  const savings = sanitize(rawBody.savings);
  const climate = sanitize(rawBody.climate);
  const workStyle = sanitize(rawBody.workStyle);
  const healthcare = sanitize(rawBody.healthcare);

  // Input Validation - Check all fields exist
  if (!nationality || !age || !profession || !budget || !languages || !reason || 
      !priorities || !family || !govtype || !education || !experience || 
      !savings || !climate || !workStyle || !healthcare) {
    return res.status(400).json({
      error: 'All profile fields are required to generate a complete 24-topic settlement report.'
    });
  }

  const prompt = `You are SettleIQ, the world's most comprehensive AI immigration advisor. A user wants to permanently settle abroad.

USER PROFILE:
- Nationality/Passport: ${nationality}
- Age Range: ${age}
- Profession/Skill: ${profession}
- Education Level: ${education}
- Work Experience: ${experience}
- Monthly Budget (USD): ${budget}
- Current Savings: ${savings}
- Work Style: ${workStyle}
- Language Skills: ${languages}
- Climate Preference: ${climate}
- Healthcare Priority: ${healthcare}
- Primary Reason for Moving: ${reason}
- Top Settlement Priority: ${priorities}
- Family Situation: ${family}
- Government Preference: ${govtype}

Recommend the TOP 3 countries for this person to settle permanently.

For EACH country, provide DEEP analysis covering ALL these topics:

1. IT/PROFESSIONAL JOB MARKET
2. SALARY & NET INCOME
3. COST OF LIVING (monthly breakdown)
4. SAVINGS POTENTIAL
5. WORK-LIFE BALANCE
6. LEAVE & HOLIDAYS
7. VISA PROCESS
8. PERMANENT RESIDENCY PATH
9. CITIZENSHIP PATH
10. HEALTHCARE
11. SAFETY & SOCIAL ENVIRONMENT
12. CLIMATE & WEATHER
13. LANGUAGE SITUATION
14. HOME COUNTRY COMMUNITY
15. TAXES & BENEFITS
16. JOB SECURITY & LABOR LAWS
17. PUBLIC TRANSPORT
18. RETIREMENT & PENSION
19. DIGITAL INFRASTRUCTURE
20. LIFESTYLE & MENTAL WELLBEING
21. DUAL CITIZENSHIP RULES
22. WAR, POLITICAL STABILITY & FUTURE SAFETY
23. RELOCATION COST ESTIMATE
24. PERSONALIZED FIT SCORE BREAKDOWN

Return ONLY valid JSON. No text outside JSON. Structure:
{
  "summary": "2-3 sentence overview of analysis tailored to ${nationality} passport",
  "bestMatch": "Country Name",
  "countries": [
    {
      "name": "Country Name",
      "flag": "emoji",
      "matchScore": 95,
      "visaPathway": "Specific visa name",
      "relocationCost": "$X,000 - $Y,000 USD",
      "jobMarket": "detailed paragraph",
      "salary": {
        "gross": "$X,000/month",
        "netTakeHome": "$X,000/month",
        "taxRate": "X%",
        "annualNet": "$XX,000/year"
      },
      "costOfLiving": {
        "rent": "$X,000/month",
        "groceries": "$XXX/month",
        "transport": "$XXX/month",
        "total": "$X,XXX/month"
      },
      "monthlySavings": "$X,000/month",
      "workLifeBalance": "detailed paragraph",
      "leavePolicy": "X days paid + X public holidays",
      "visaProcess": "detailed paragraph",
      "prTimeline": "X years with conditions",
      "citizenshipTimeline": "X years total",
      "dualCitizenship": "Yes/No + details",
      "languageTest": "Required/Not required + details",
      "healthcare": "detailed paragraph",
      "safety": {
        "gpiRanking": "#X globally (GPI 2026)",
        "crimeLevel": "Very Low/Low/Moderate",
        "foreignerSafety": "paragraph"
      },
      "climate": "detailed paragraph with temperatures",
      "language": "detailed paragraph",
      "homeCommunity": "paragraph about expat community",
      "taxes": "detailed paragraph",
      "jobSecurity": "paragraph",
      "transport": "paragraph",
      "retirement": "paragraph",
      "digital": "paragraph",
      "lifestyle": "paragraph",
      "politicalStability": "paragraph",
      "warRisk": "Low/Medium/High + explanation",
      "personalizedReason": "Why this specifically suits this person",
      "scores": {
        "career": 9,
        "financial": 8,
        "lifestyle": 9,
        "immigrationEase": 8,
        "safety": 10,
        "climate": 7
      },
      "pros": ["pro1", "pro2", "pro3", "pro4", "pro5"],
      "cons": ["con1", "con2", "con3"]
    }
  ],
  "comparisonTable": {
    "factors": ["Match Score", "Net Monthly Salary", "Monthly Cost", "Monthly Savings", "PR Timeline", "Citizenship", "Dual Citizenship", "GPI Ranking", "Tax Rate"],
    "data": {
      "Country 1 Name": ["95/100", "$X,000", "$X,000", "$X,000", "X years", "X years", "Yes", "#X", "X%"],
      "Country 2 Name": ["..."],
      "Country 3 Name": ["..."]
    }
  },
  "runnerUps": [
    {"name": "Country", "flag": "emoji", "briefReason": "why it's worth considering"}
  ],
  "finalVerdict": "2-3 paragraph honest final recommendation explaining exactly which country and why for THIS specific person"
}`;

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'GEMINI_API_KEY is not configured on the server.' });
    }

    const apiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            responseMimeType: "application/json"
          }
        })
      }
    );

    const data = await apiResponse.json();

    if (!apiResponse.ok || !data.candidates || !data.candidates[0]) {
      const errMsg = data.error ? data.error.message : 'No candidate response returned by Gemini AI.';
      console.error('Gemini API Error:', errMsg);
      return res.status(500).json({ error: errMsg });
    }

    const text = data.candidates[0].content.parts[0].text;
    let parsedResult = extractAndParseJSON(text);

    if (!parsedResult) {
      parsedResult = { rawText: text };
    }

    // Extract recommended country names for logging evidence
    let recommendedNames = 'N/A';
    if (parsedResult && parsedResult.countries && Array.isArray(parsedResult.countries)) {
      recommendedNames = parsedResult.countries.map(c => c.name).join(', ');
    }

    // Log request as competition proof of production AI execution
    logRequest({ nationality, profession, budget, recommendedCountries: recommendedNames });

    return res.json({ result: parsedResult });

  } catch (error) {
    console.error('Server error:', error.message);
    return res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 SettleIQ running on http://localhost:${PORT}`);
});