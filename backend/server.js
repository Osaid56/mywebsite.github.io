require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { neon } = require('@neondatabase/serverless');

const app = express();
app.use(express.json());
app.use(cors({
  origin: ['https://osaid56.github.io', 'https://aibyosaid.vercel.app', 'http://localhost:8080', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
// Handle preflight requests explicitly for Vercel
app.options('*', cors());

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_dev_key_123';
const PORT = process.env.PORT || 5001;

// --- Neon PostgreSQL Connection ---
const sql = neon(process.env.DATABASE_URL);

// --- AI Provider Fallback Chain ---
// Priority: Cerebras (fastest) → xAI → Gemini → OpenRouter → HuggingFace
// If one fails (rate limit, error), the next is tried automatically.
const AI_PROVIDERS = [
  {
    name: 'Cerebras',
    url: 'https://api.cerebras.ai/v1/chat/completions',
    apiKey: process.env.CEREBRAS_API_KEY,
    model: 'llama3.1-8b',
    headers: (key) => ({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    }),
  },
  {
    name: 'xAI (Grok)',
    url: 'https://api.x.ai/v1/chat/completions',
    apiKey: process.env.XAI_API_KEY,
    model: 'grok-3-mini',
    headers: (key) => ({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    }),
  },
  {
    name: 'Google Gemini',
    url: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    apiKey: process.env.GEMINI_API_KEY,
    model: 'gemini-2.0-flash',
    headers: (key) => ({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    }),
  },
  {
    name: 'OpenRouter',
    url: 'https://openrouter.ai/api/v1/chat/completions',
    apiKey: process.env.OPENROUTER_API_KEY,
    model: 'meta-llama/llama-4-scout',
    headers: (key) => ({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
      'HTTP-Referer': 'https://osai.app',
      'X-Title': 'OS AI',
    }),
  },
  {
    name: 'HuggingFace',
    url: 'https://router.huggingface.co/v1/chat/completions',
    apiKey: process.env.HF_API_KEY,
    model: 'meta-llama/Llama-3.1-8B-Instruct',
    headers: (key) => ({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
    }),
  },
];

// --- Initialize Database Tables (lazy — runs once on first request) ---
let dbInitialized = false;
async function initDB() {
  if (dbInitialized) return;
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS osai_users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS osai_chats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES osai_users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS osai_messages (
        id SERIAL PRIMARY KEY,
        chat_id INTEGER REFERENCES osai_chats(id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;
    dbInitialized = true;
    console.log('✅ Neon PostgreSQL connected & tables ready');
  } catch (err) {
    console.error('❌ Database init failed:', err.message);
  }
}

// Run DB init as middleware (lazy for Vercel, eager locally)
app.use(async (req, res, next) => {
  await initDB();
  next();
});

// --- Auth Middleware (optional — returns userId or null) ---
const optionalAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    req.userId = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
  } catch (err) {
    req.userId = null;
  }
  next();
};

const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized — please log in.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// =====================
// AUTHENTICATION ROUTES
// =====================

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || username.length < 4) return res.status(400).json({ error: 'Username must be at least 4 characters' });
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await sql`SELECT id FROM osai_users WHERE username = ${username}`;
    if (existing.length > 0) return res.status(400).json({ error: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await sql`
      INSERT INTO osai_users (username, password) VALUES (${username}, ${hashedPassword}) RETURNING id, username
    `;
    const user = result[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await sql`SELECT id, username, password FROM osai_users WHERE username = ${username}`;
    if (result.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

    const user = result[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =====================
// CHAT HISTORY ROUTES (requires login)
// =====================

app.get('/api/chats', requireAuth, async (req, res) => {
  try {
    const chats = await sql`
      SELECT id, title, created_at, updated_at
      FROM osai_chats
      WHERE user_id = ${req.userId}
      ORDER BY updated_at DESC
    `;

    // For each chat, fetch its messages
    const result = await Promise.all(
      chats.map(async (chat) => {
        const messages = await sql`
          SELECT role, content FROM osai_messages
          WHERE chat_id = ${chat.id}
          ORDER BY created_at ASC
        `;
        return {
          _id: chat.id,
          title: chat.title,
          createdAt: chat.created_at,
          updatedAt: chat.updated_at,
          messages,
        };
      })
    );

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/chats', requireAuth, async (req, res) => {
  try {
    const { title, messages } = req.body;

    const chatResult = await sql`
      INSERT INTO osai_chats (user_id, title) VALUES (${req.userId}, ${title}) RETURNING id
    `;
    const chatId = chatResult[0].id;

    // Insert all messages
    for (const msg of messages) {
      await sql`
        INSERT INTO osai_messages (chat_id, role, content) VALUES (${chatId}, ${msg.role}, ${msg.content})
      `;
    }

    res.json({ _id: chatId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/chats/:id', requireAuth, async (req, res) => {
  try {
    const chatId = parseInt(req.params.id);
    const { messages } = req.body;

    // Verify ownership
    const chat = await sql`SELECT id FROM osai_chats WHERE id = ${chatId} AND user_id = ${req.userId}`;
    if (chat.length === 0) return res.status(404).json({ error: 'Chat not found' });

    // Delete old messages and re-insert (simplest approach for full replacement)
    await sql`DELETE FROM osai_messages WHERE chat_id = ${chatId}`;
    for (const msg of messages) {
      await sql`
        INSERT INTO osai_messages (chat_id, role, content) VALUES (${chatId}, ${msg.role}, ${msg.content})
      `;
    }

    // Update timestamp
    await sql`UPDATE osai_chats SET updated_at = NOW() WHERE id = ${chatId}`;

    res.json({ _id: chatId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =====================
// AI CHAT COMPLETIONS (no login required — guests can use)
// =====================

app.post('/api/chat/completions', optionalAuth, async (req, res) => {
  const { messages, max_completion_tokens, temperature, top_p } = req.body;

  let lastError = null;

  for (const provider of AI_PROVIDERS) {
    if (!provider.apiKey) continue; // skip if key not configured

    try {
      console.log(`🤖 Trying provider: ${provider.name}...`);

      const body = {
        model: provider.model,
        messages,
        max_completion_tokens: max_completion_tokens || 1024,
        temperature: temperature ?? 0.2,
        top_p: top_p ?? 1,
        stream: false,
      };

      const response = await fetch(provider.url, {
        method: 'POST',
        headers: provider.headers(provider.apiKey),
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (response.ok && data.choices && data.choices.length > 0) {
        console.log(`✅ Success from ${provider.name}`);
        // Add metadata about which provider was used
        data._provider = provider.name;
        return res.json(data);
      }

      // If rate-limited or server error, try next provider
      if (response.status === 429 || response.status >= 500) {
        console.log(`⚠️ ${provider.name} returned ${response.status}, trying next...`);
        lastError = data.error?.message || `${provider.name} returned ${response.status}`;
        continue;
      }

      // Other client errors (400, 401, 403) — also try next
      console.log(`⚠️ ${provider.name} returned ${response.status}: ${JSON.stringify(data.error || data)}`);
      lastError = data.error?.message || `${provider.name} error: ${response.status}`;
      continue;

    } catch (err) {
      console.log(`❌ ${provider.name} network error: ${err.message}`);
      lastError = `${provider.name}: ${err.message}`;
      continue;
    }
  }

  // All providers failed
  res.status(503).json({
    error: {
      message: `All AI providers exhausted. Last error: ${lastError}`,
    },
  });
});

// =====================
// EXPORT FOR VERCEL + LOCAL DEV
// =====================

// Export for Vercel serverless
module.exports = app;

// Only listen locally (Vercel handles this in production)
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => console.log(`🚀 OS AI Server running on port ${PORT}`));
}
