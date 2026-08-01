const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

dotenv.config();

console.log('API Key loaded:', process.env.GEMINI_API_KEY ? 'YES' : 'NO');

const app = express();
app.set('trust proxy', 1);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(cors({
  origin: [
    'https://settleiq-newb.onrender.com',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(generalLimiter);

const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'AI report limit reached. Try again in 1 hour.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/analyze', aiLimiter);

app.use(express.static('public'));

app.use((req, res, next) => {
  const log = `${new Date().toISOString()} | ${req.method} | ${req.path} | IP: ${req.ip}\n`;
  fs.appendFile(path.join(__dirname, 'logs.txt'), log, (err) => {
    if (err) console.error('Failed to append to logs.txt:', err.message);
  });
  next();
});

function sanitize(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[^\w\s\-\.,\/\(\)\$\+\%\:\;]/gi, '')
    .trim()
    .slice(0, 500);
}

function extractAndParseJSON(rawText) {
  if (!rawText || typeof rawText !== 'string') return null;

  let clean = rawText
    .replace(/```json/gi, '')
    .replace(/```/g, '')
    .trim();

  const start = clean.indexOf('{');
  const end = clean.lastIndexOf('}');
  if (start !== -1 && end !== -1 && end > start) {
    clean = clean.substring(start, end + 1);
  }

  try { return JSON.parse(clean); } catch(e1) {}

  try {
    const fixed = clean
      .replace(/,\s*([\]}])/g, '$1')
      .replace(/([{,]\s*)(\w+)(\s*:)/g, '$1"$2"$3')
      .replace(/:\s*'([^']*)'/g, ': "$1"')
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
      .replace(/\\'/g, "'")
      .replace(/([^\\])\\([^"\\\/bfnrtu])/g, '$1\\\\$2');
    return JSON.parse(fixed);
  } catch(e2) {}

  try {
    const countriesMatch = clean.match(/"countries"\s*:\s*(\[[\s\S]*?\])\s*,\s*"comparisonTable"/);
    if (countriesMatch) {
      const partial = '{"countries":' + countriesMatch[1] + ',"comparisonTable":{},"summary":"Report generated.","finalVerdict":"See country cards above.","bestMatch":""}';
      return JSON.parse(partial);
    }
  } catch(e3) {}

  return null;
}

app.post('/analyze', async (req, res) => {
  try {
    const rawBody = req.body || {};
    console.log('Incoming /analyze request for profession:', rawBody.profession, '| nationality:', rawBody.nationality);

    const nationality = sanitize(rawBody.nationality || 'India');
    const age = sanitize(String(rawBody.age || '28'));
    const gender = sanitize(rawBody.gender || 'Prefer not to say');
    const profession = sanitize(rawBody.profession || 'Professional');
    const budget = sanitize(String(rawBody.budget || '50000'));
    const currency = sanitize(rawBody.currency || 'INR');
    const languages = sanitize(rawBody.languages || 'English only');
    const reason = sanitize(rawBody.reason || 'Better career & high income');
    const priorities = sanitize(rawBody.priorities || 'fast PR and citizenship');
    const family = sanitize(rawBody.family || 'single');
    const govtype = sanitize(rawBody.govtype || 'democratic and welcoming to immigrants');
    const education = sanitize(rawBody.education || "Bachelor's Degree");
    const experience = sanitize(rawBody.experience || '3-5 years');
    const savings = sanitize(rawBody.savings || '$20,000 - $50,000');
    const climate = sanitize(rawBody.climate || 'Warm and sunny');
    const workStyle = sanitize(rawBody.workStyle || 'Office job');
    const healthcare = sanitize(rawBody.healthcare || 'Universal free healthcare');
    const additionalContext = sanitize(rawBody.additionalContext || '');

    const prompt = `You are SettleIQ, the world's premier AI immigration advisor for the Build with Gemini XPRIZE. A user wants to permanently settle abroad.

USER PROFILE:
- Passport Nationality: ${nationality}
- User age: ${age} years old
- Gender: ${gender}
- Profession/Skill: ${profession}
- Education Level: ${education}
- Work Experience: ${experience}
- Current Monthly Expenses (Home Country): ${budget} ${currency}
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

Convert the user's current monthly expenses (${budget} ${currency}) to USD equivalent and use it to calculate:
1. What lifestyle this budget supports in each recommended country
2. Whether the user needs a salary increase or can maintain their current lifestyle
3. PPP-adjusted comparison — how far this money goes in each country
4. Estimated monthly expenses in each recommended country in both USD and their home currency (${currency})

CRITICAL REQUIREMENTS FOR YOUR RESPONSE:
- Minimum 300 words per country section
- Every metric must have an actual specific value — no placeholders, vague text, or TBD statements
- Salary figures: specific monthly amounts for ${profession} in that country (gross and net after tax)
- PR timeline: specific years with exact visa route name calculated for a ${age} year old applicant
- Citizenship timeline: specific years from arrival
- Job market: name 5 actual companies hiring ${profession} in that country
- Cost of living breakdown: rent + food + transport + utilities separately
- Include a RED FLAGS section per country (honest risks, challenges, and visa hurdles)
- End with ranked verdict:
  Best for income: [country]
  Best for lifestyle: [country]
  Best for fastest PR: [country]
- Do NOT use emoji for ratings — use text like Excellent (5/5) or Good (4/5) or numeric scores like 8/10
- Factor age (${age}) specifically into PR points systems and residency qualification timelines.

Recommend the TOP 3 countries for this person to settle permanently.

Return ONLY valid JSON. No text outside JSON. Structure:
{
  "summary": "Detailed 2-3 sentence overview of analysis tailored to ${nationality} passport, age ${age}, and user preferences.",
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
      "budgetEquivalent": "${budget} ${currency}/month = ~$X USD = Y local currency in Country Name (covers basic/comfortable lifestyle)",
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
      "personalizedReason": "Why this specifically suits the user profile and additional context.",
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

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error('Error: GEMINI_API_KEY is missing from environment variables.');
      return res.status(500).json({ error: 'GEMINI_API_KEY is not configured on the server.' });
    }

    const maxRetries = 3;
    let apiResponse = null;
    let data = null;
    let isBusyError = false;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      console.log(`Sending request to Gemini 3.5 Flash API (attempt ${attempt}/${maxRetries})...`);

      try {
        apiResponse = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: prompt }] }],
              generationConfig: {
                temperature: 1,
                maxOutputTokens: 65536
              }
            })
          }
        );

        data = await apiResponse.json();

        const statusIs503 = apiResponse.status === 503;
        const errText = JSON.stringify(data || {}).toLowerCase();
        isBusyError = statusIs503 || errText.includes('high demand') || errText.includes('temporarily unavailable') || errText.includes('resource_exhausted') || errText.includes('overloaded');

        if (apiResponse.ok && data.candidates && data.candidates[0]) {
          break;
        }

        if (isBusyError) {
          console.warn(`Gemini API busy (503 / high demand). Attempt ${attempt}/${maxRetries} failed.`);
          if (attempt < maxRetries) {
            console.log('Waiting 5 seconds before retrying attempt...');
            await new Promise(r => setTimeout(r, 5000));
            continue;
          }
        } else {
          break;
        }
      } catch (fetchErr) {
        console.error(`Fetch attempt ${attempt} error:`, fetchErr.message);
        if (attempt < maxRetries) {
          console.log('Waiting 5 seconds before retrying attempt...');
          await new Promise(r => setTimeout(r, 5000));
        }
      }
    }

    if (isBusyError && (!apiResponse || !apiResponse.ok || !data || !data.candidates || !data.candidates[0])) {
      return res.status(503).json({ error: 'Our AI is busy right now. Please try again in 30 seconds.' });
    }

    if (!apiResponse || !apiResponse.ok || !data || !data.candidates || !data.candidates[0]) {
      const errMsg = (data && data.error) ? data.error.message : 'No candidate response returned by Gemini AI.';
      console.error('Gemini API Error details:', (data && data.error) || data);
      return res.status(500).json({ error: errMsg });
    }

    const text = data.candidates[0].content.parts[0].text;
    let parsedResult = extractAndParseJSON(text);

    if (!parsedResult) {
      parsedResult = { rawText: text };
    }

    console.log('Successfully generated settlement report via Gemini 3.5 Flash!');
    return res.json({ result: parsedResult });

  } catch (error) {
    console.error('Full error in /analyze:', error);
    console.error('Error message:', error.message);
    console.error('Stack:', error.stack);
    return res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.use((err, req, res, next) => {
  console.error('Global error handler caught:', err.message);
  res.status(500).json({
    error: 'Something went wrong. Please try again.'
  });
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err.message);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SettleIQ running on http://localhost:${PORT}`);
});