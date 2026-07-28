const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

dotenv.config();
const app = express();

// Security Headers - Fixed for Firebase Auth Popup Communication & Render Deployment
app.use(helmet({
  contentSecurityPolicy: false, // Disables default CSP so CDN scripts, marked, & Firebase work cleanly
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }, // Allows popup window (window.opener) to communicate with Firebase auth handler
  crossOriginEmbedderPolicy: false
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
    .slice(0, 500);
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
  const additionalContext = sanitize(rawBody.additionalContext || '');

  // Input Validation - Check all profile fields exist
  if (!nationality || !age || !profession || !budget || !languages || !reason || 
      !priorities || !family || !govtype || !education || !experience || 
      !savings || !climate || !workStyle || !healthcare) {
    return res.status(400).json({
      error: 'All profile fields are required to generate a complete 24-topic settlement report.'
    });
  }

  const prompt = `You are SettleIQ, the world's premier AI immigration advisor for the Build with Gemini XPRIZE. A user wants to permanently settle abroad.

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
- Additional Personal Context: ${additionalContext || 'None provided'}

CRITICAL REQUIREMENTS FOR YOUR RESPONSE:
- Minimum 300 words per country section
- Every metric must have an actual specific value — no placeholders, vague text, or TBD statements
- Salary figures: specific monthly amounts for ${profession} in that country (gross and net after tax)
- PR timeline: specific years with exact visa route name
- Citizenship timeline: specific years from arrival
- Job market: name 5 actual companies hiring ${profession} in that country
- Cost of living breakdown: rent + food + transport + utilities separately
- Include a RED FLAGS section per country (honest risks, challenges, and visa hurdles)
- End with ranked verdict:
  Best for income: [country]
  Best for lifestyle: [country]  
  Best for fastest PR: [country]
- Do NOT use emoji for ratings — use text like Excellent (5/5) or Good (4/5) or numeric scores like 8/10
- Parse any preferences in Additional Personal Context (e.g. dogs, ocean/beach, halal food, elderly parents, school age children, spouse profession) and factor them into country selection and analysis.

Recommend the TOP 3 countries for this person to settle permanently.

Return ONLY valid JSON. No text outside JSON. Structure:
{
  "summary": "Detailed 2-3 sentence overview of analysis tailored to ${nationality} passport and user preferences.",
  "bestMatch": "Country Name",
  "rankedVerdict": {
    "bestForIncome": "Country Name — Brief reason",
    "bestForLifestyle": "Country Name — Brief reason",
    "bestForFastestPR": "Country Name — Brief reason"
  },
  "countries": [
    {
      "name": "Country Name",
      "flag": "emoji",
      "matchScore": 95,
      "visaPathway": "Specific visa route name",
      "relocationCost": "$X,000 - $Y,000 USD",
      "jobMarket": "Detailed paragraph analyzing job demand for ${profession}.",
      "hiringCompanies": ["Company 1", "Company 2", "Company 3", "Company 4", "Company 5"],
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
        "utilities": "$XXX/month",
        "total": "$X,XXX/month"
      },
      "monthlySavings": "$X,000/month",
      "workLifeBalance": "Detailed paragraph on work culture.",
      "leavePolicy": "X days paid annual leave + X public holidays",
      "visaProcess": "Detailed paragraph explaining requirements.",
      "prTimeline": "X years via specific visa pathway",
      "citizenshipTimeline": "X years total",
      "dualCitizenship": "Allowed / Allowed with conditions / Not allowed",
      "languageTest": "Required level / Not required",
      "healthcare": "Detailed paragraph on health system.",
      "safety": {
        "gpiRanking": "#X globally (GPI 2026)",
        "crimeLevel": "Very Low / Low / Moderate",
        "foreignerSafety": "Detailed paragraph"
      },
      "climate": "Detailed paragraph",
      "language": "Detailed paragraph",
      "homeCommunity": "Paragraph on expat community",
      "taxes": "Detailed paragraph",
      "jobSecurity": "Paragraph",
      "transport": "Paragraph",
      "retirement": "Paragraph",
      "digital": "Paragraph",
      "lifestyle": "Paragraph",
      "politicalStability": "Paragraph",
      "warRisk": "Low / Medium / High — explanation",
      "personalizedReason": "Why this specifically suits the user's profile and additional context.",
      "scores": {
        "career": 9,
        "financial": 8,
        "lifestyle": 9,
        "immigrationEase": 8,
        "safety": 10,
        "climate": 7
      },
      "pros": ["Pro 1", "Pro 2", "Pro 3", "Pro 4", "Pro 5"],
      "cons": ["Con 1", "Con 2", "Con 3"],
      "redFlags": ["Red flag 1", "Red flag 2", "Red flag 3"]
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
    {"name": "Country", "flag": "emoji", "briefReason": "why it is worth considering"}
  ],
  "finalVerdict": "Detailed final recommendation paragraph explaining exact country choice for THIS specific user."
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