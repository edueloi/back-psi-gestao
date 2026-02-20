require("dotenv").config();

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const XLSX = require("xlsx");

const { db, initDb } = require("./db");
const { parseImportedText, parseImportedRows } = require("./importers");

initDb();

const app = express();
const upload = multer({ dest: path.join(__dirname, "..", "tmp") });

const DEFAULT_PORT = 3001;
let PORT = Number(process.env.PORT || DEFAULT_PORT);
const API_PREFIX = process.env.API_PREFIX || "/api";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://psigestao.develoi.com";

const extraOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const allowedOrigins = new Set([
  FRONTEND_ORIGIN,
  "https://psigestao.develoi.com",
  "http://localhost:5173",
  "http://localhost:4200",
  "http://127.0.0.1:5173",
  "https://66ji86xsmr1k42e90gv4z7unefgcefnkjzq5j1xy5qjq465gdm-h868144788.scf.usercontent.goog",
  "https://3vhtj365771gsxzpm0l07lr0hn205uig18f642tjn66ix0bkq8-h868144788.scf.usercontent.goog",
  ...extraOrigins,
]);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked: ${origin}`), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(express.json({ limit: "15mb" }));

const PUBLIC_DIR = path.join(__dirname, "..", "public");
app.use(express.static(PUBLIC_DIR));

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

function nowIso() {
  return new Date().toISOString();
}

function newId(prefix) {
  if (crypto.randomUUID) return `${prefix}-${crypto.randomUUID()}`;
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function toTransaction(row) {
  return {
    id: row.id,
    userId: row.user_id,
    date: row.date,
    description: row.description,
    payerName: row.payer_name,
    beneficiaryName: row.beneficiary_name,
    amount: Number(row.amount),
    type: row.type,
    category: row.category,
    method: row.method,
    status: row.status,
    receiptStatus: row.receipt_status,
    tags: JSON.parse(row.tags || "[]"),
    isRecurring: Boolean(row.is_recurring),
    payerCpf: row.payer_cpf,
    beneficiaryCpf: row.beneficiary_cpf,
    observation: row.observation,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    crp: row.crp,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function calcSummary(userId) {
  const where = userId ? "WHERE user_id = ?" : "";
  const args = userId ? [userId] : [];

  const incomeRow = db.prepare(`SELECT COALESCE(SUM(amount),0) AS value FROM transactions ${where} ${where ? "AND" : "WHERE"} type = 'INCOME'`).get(...args);
  const expenseRow = db.prepare(`SELECT COALESCE(SUM(amount),0) AS value FROM transactions ${where} ${where ? "AND" : "WHERE"} type = 'EXPENSE'`).get(...args);

  const totalIncome = Number(incomeRow.value || 0);
  const totalExpense = Number(expenseRow.value || 0);
  const netResult = totalIncome - totalExpense;

  const rules = [
    { name: "INSS Autonomo", percentage: 20, base: "GROSS" },
    { name: "IRPF Estimado", percentage: 15, base: "NET" },
    { name: "Reserva de Ferias", percentage: 8.33, base: "NET" },
    { name: "Reserva 13/Emergencia", percentage: 10, base: "NET" },
  ];

  const provisions = rules.map((rule) => {
    const base = rule.base === "GROSS" ? totalIncome : Math.max(0, netResult);
    return {
      name: rule.name,
      amount: base * (rule.percentage / 100),
    };
  });

  const totalProvisions = provisions.reduce((acc, item) => acc + item.amount, 0);

  return {
    totalIncome,
    totalExpense,
    netResult,
    provisions,
    liquidResult: netResult - totalProvisions,
  };
}

function buildTransactionPayload(body, isPatch) {
  const payload = {
    userId: body.userId ?? null,
    date: body.date,
    description: body.description,
    payerName: body.payerName ?? null,
    beneficiaryName: body.beneficiaryName ?? null,
    amount: body.amount,
    type: body.type,
    category: body.category,
    method: body.method,
    status: body.status || "PAID",
    receiptStatus: body.receiptStatus ?? null,
    tags: Array.isArray(body.tags) ? body.tags : [],
    isRecurring: Boolean(body.isRecurring),
    payerCpf: body.payerCpf ?? null,
    beneficiaryCpf: body.beneficiaryCpf ?? null,
    observation: body.observation ?? null,
  };

  if (isPatch) {
    const clean = {};
    Object.keys(payload).forEach((key) => {
      if (body[key] !== undefined) clean[key] = payload[key];
    });
    return clean;
  }

  const required = ["date", "description", "amount", "type", "category", "method"];
  for (const key of required) {
    if (payload[key] === undefined || payload[key] === null || payload[key] === "") {
      throw new Error(`Missing required field: ${key}`);
    }
  }

  return payload;
}

function removeTmpFile(file) {
  if (!file || !file.path) return;
  try {
    fs.unlinkSync(file.path);
  } catch (err) {
    // no-op
  }
}

const router = express.Router();

router.get("/health", (req, res) => {
  res.json({ ok: true, service: "psigestao-api", timestamp: nowIso() });
});

router.get("/users", (req, res) => {
  const rows = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  res.json(rows.map(toUser));
});

router.get("/users/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ message: "User not found" });
  res.json(toUser(row));
});

router.post("/users", (req, res) => {
  const id = newId("usr");
  const now = nowIso();
  const user = {
    id,
    name: req.body.name,
    email: req.body.email,
    passwordHash: req.body.passwordHash || null,
    crp: req.body.crp || null,
    createdAt: now,
    updatedAt: now,
  };

  if (!user.name || !user.email) {
    return res.status(400).json({ message: "name and email are required" });
  }

  db.prepare(
    `INSERT INTO users (id, name, email, password_hash, crp, created_at, updated_at)
     VALUES (@id, @name, @email, @passwordHash, @crp, @createdAt, @updatedAt)`
  ).run(user);

  const created = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  res.status(201).json(toUser(created));
});

router.put("/users/:id", (req, res) => {
  const existing = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!existing) return res.status(404).json({ message: "User not found" });

  const name = req.body.name;
  const email = req.body.email;
  const crp = req.body.crp || null;
  const passwordHash = req.body.passwordHash || existing.password_hash;

  if (!name || !email) {
    return res.status(400).json({ message: "name and email are required" });
  }

  db.prepare(
    `UPDATE users
     SET name = ?, email = ?, crp = ?, password_hash = ?, updated_at = ?
     WHERE id = ?`
  ).run(name, email, crp, passwordHash, nowIso(), req.params.id);

  const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  res.json(toUser(updated));
});

router.patch("/users/:id", (req, res) => {
  const existing = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  if (!existing) return res.status(404).json({ message: "User not found" });

  const name = req.body.name ?? existing.name;
  const email = req.body.email ?? existing.email;
  const crp = req.body.crp !== undefined ? req.body.crp : existing.crp;
  const passwordHash = req.body.passwordHash !== undefined ? req.body.passwordHash : existing.password_hash;

  db.prepare(
    `UPDATE users
     SET name = ?, email = ?, crp = ?, password_hash = ?, updated_at = ?
     WHERE id = ?`
  ).run(name, email, crp, passwordHash, nowIso(), req.params.id);

  const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
  res.json(toUser(updated));
});

router.delete("/users/:id", (req, res) => {
  const result = db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ message: "User not found" });
  res.status(204).send();
});

router.get("/transactions", (req, res) => {
  const { userId, type, from, to, q } = req.query;

  const where = [];
  const args = [];

  if (userId) {
    where.push("user_id = ?");
    args.push(userId);
  }
  if (type) {
    where.push("type = ?");
    args.push(type);
  }
  if (from) {
    where.push("date >= ?");
    args.push(from);
  }
  if (to) {
    where.push("date <= ?");
    args.push(to);
  }
  if (q) {
    where.push("(description LIKE ? OR category LIKE ? OR payer_name LIKE ? OR beneficiary_name LIKE ?)");
    const search = `%${q}%`;
    args.push(search, search, search, search);
  }

  const sqlWhere = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const rows = db.prepare(`SELECT * FROM transactions ${sqlWhere} ORDER BY date DESC, created_at DESC`).all(...args);
  res.json(rows.map(toTransaction));
});

router.get("/transactions/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM transactions WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ message: "Transaction not found" });
  res.json(toTransaction(row));
});

router.post("/transactions", (req, res) => {
  let payload;
  try {
    payload = buildTransactionPayload(req.body, false);
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }

  const now = nowIso();
  const id = req.body.id || newId("txn");

  db.prepare(
    `INSERT INTO transactions (
      id, user_id, date, description, payer_name, beneficiary_name, amount,
      type, category, method, status, receipt_status, tags, is_recurring,
      payer_cpf, beneficiary_cpf, observation, created_at, updated_at
    ) VALUES (
      @id, @user_id, @date, @description, @payer_name, @beneficiary_name, @amount,
      @type, @category, @method, @status, @receipt_status, @tags, @is_recurring,
      @payer_cpf, @beneficiary_cpf, @observation, @created_at, @updated_at
    )`
  ).run({
    id,
    user_id: payload.userId,
    date: payload.date,
    description: payload.description,
    payer_name: payload.payerName,
    beneficiary_name: payload.beneficiaryName,
    amount: Number(payload.amount),
    type: payload.type,
    category: payload.category,
    method: payload.method,
    status: payload.status,
    receipt_status: payload.receiptStatus,
    tags: JSON.stringify(payload.tags),
    is_recurring: payload.isRecurring ? 1 : 0,
    payer_cpf: payload.payerCpf,
    beneficiary_cpf: payload.beneficiaryCpf,
    observation: payload.observation,
    created_at: now,
    updated_at: now,
  });

  const created = db.prepare("SELECT * FROM transactions WHERE id = ?").get(id);
  res.status(201).json(toTransaction(created));
});

router.put("/transactions/:id", (req, res) => {
  const existing = db.prepare("SELECT * FROM transactions WHERE id = ?").get(req.params.id);
  if (!existing) return res.status(404).json({ message: "Transaction not found" });

  let payload;
  try {
    payload = buildTransactionPayload(req.body, false);
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }

  db.prepare(
    `UPDATE transactions SET
      user_id = @user_id,
      date = @date,
      description = @description,
      payer_name = @payer_name,
      beneficiary_name = @beneficiary_name,
      amount = @amount,
      type = @type,
      category = @category,
      method = @method,
      status = @status,
      receipt_status = @receipt_status,
      tags = @tags,
      is_recurring = @is_recurring,
      payer_cpf = @payer_cpf,
      beneficiary_cpf = @beneficiary_cpf,
      observation = @observation,
      updated_at = @updated_at
     WHERE id = @id`
  ).run({
    id: req.params.id,
    user_id: payload.userId,
    date: payload.date,
    description: payload.description,
    payer_name: payload.payerName,
    beneficiary_name: payload.beneficiaryName,
    amount: Number(payload.amount),
    type: payload.type,
    category: payload.category,
    method: payload.method,
    status: payload.status,
    receipt_status: payload.receiptStatus,
    tags: JSON.stringify(payload.tags),
    is_recurring: payload.isRecurring ? 1 : 0,
    payer_cpf: payload.payerCpf,
    beneficiary_cpf: payload.beneficiaryCpf,
    observation: payload.observation,
    updated_at: nowIso(),
  });

  const updated = db.prepare("SELECT * FROM transactions WHERE id = ?").get(req.params.id);
  res.json(toTransaction(updated));
});

router.patch("/transactions/:id", (req, res) => {
  const existing = db.prepare("SELECT * FROM transactions WHERE id = ?").get(req.params.id);
  if (!existing) return res.status(404).json({ message: "Transaction not found" });

  let payload;
  try {
    payload = buildTransactionPayload(req.body, true);
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }

  const map = {
    userId: "user_id",
    date: "date",
    description: "description",
    payerName: "payer_name",
    beneficiaryName: "beneficiary_name",
    amount: "amount",
    type: "type",
    category: "category",
    method: "method",
    status: "status",
    receiptStatus: "receipt_status",
    tags: "tags",
    isRecurring: "is_recurring",
    payerCpf: "payer_cpf",
    beneficiaryCpf: "beneficiary_cpf",
    observation: "observation",
  };

  const sets = [];
  const values = [];

  Object.keys(payload).forEach((key) => {
    const column = map[key];
    if (!column) return;

    let value = payload[key];
    if (key === "tags") value = JSON.stringify(value);
    if (key === "isRecurring") value = value ? 1 : 0;
    if (key === "amount") value = Number(value);

    sets.push(`${column} = ?`);
    values.push(value);
  });

  sets.push("updated_at = ?");
  values.push(nowIso());
  values.push(req.params.id);

  db.prepare(`UPDATE transactions SET ${sets.join(", ")} WHERE id = ?`).run(...values);

  const updated = db.prepare("SELECT * FROM transactions WHERE id = ?").get(req.params.id);
  res.json(toTransaction(updated));
});

router.delete("/transactions/:id", (req, res) => {
  const result = db.prepare("DELETE FROM transactions WHERE id = ?").run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ message: "Transaction not found" });
  res.status(204).send();
});

router.post("/transactions/:id/repeat", (req, res) => {
  const original = db.prepare("SELECT * FROM transactions WHERE id = ?").get(req.params.id);
  if (!original) return res.status(404).json({ message: "Transaction not found" });

  const baseDate = new Date(`${original.date}T00:00:00Z`);
  baseDate.setUTCMonth(baseDate.getUTCMonth() + 1);
  const nextDate = baseDate.toISOString().slice(0, 10);

  const now = nowIso();
  const id = newId("txn");

  db.prepare(
    `INSERT INTO transactions (
      id, user_id, date, description, payer_name, beneficiary_name, amount,
      type, category, method, status, receipt_status, tags, is_recurring,
      payer_cpf, beneficiary_cpf, observation, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    original.user_id,
    nextDate,
    original.description,
    original.payer_name,
    original.beneficiary_name,
    original.amount,
    original.type,
    original.category,
    original.method,
    original.status,
    original.receipt_status,
    original.tags,
    original.is_recurring,
    original.payer_cpf,
    original.beneficiary_cpf,
    original.observation,
    now,
    now
  );

  const created = db.prepare("SELECT * FROM transactions WHERE id = ?").get(id);
  res.status(201).json(toTransaction(created));
});

router.post("/transactions/import", upload.single("file"), (req, res) => {
  let parsed = { transactions: [], errors: 0 };

  try {
    if (req.file) {
      const extension = path.extname(req.file.originalname).toLowerCase();

      if (extension === ".xlsx" || extension === ".xls") {
        const wb = XLSX.readFile(req.file.path);
        const firstSheet = wb.Sheets[wb.SheetNames[0]];
        const rows = XLSX.utils.sheet_to_json(firstSheet, { header: 1 });
        parsed = parseImportedRows(rows);
      } else {
        const content = fs.readFileSync(req.file.path, "utf8");
        parsed = parseImportedText(content);
      }
    } else if (typeof req.body.text === "string") {
      parsed = parseImportedText(req.body.text);
    } else if (Array.isArray(req.body.rows)) {
      parsed = parseImportedRows(req.body.rows);
    } else if (Array.isArray(req.body.transactions)) {
      parsed = {
        transactions: req.body.transactions,
        errors: 0,
      };
    } else {
      return res.status(400).json({
        message: "Send file (multipart), text, rows[], or transactions[] to import",
      });
    }

    const insertStmt = db.prepare(
      `INSERT INTO transactions (
        id, user_id, date, description, payer_name, beneficiary_name, amount,
        type, category, method, status, receipt_status, tags, is_recurring,
        payer_cpf, beneficiary_cpf, observation, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const insertMany = db.transaction((items, userId) => {
      const now = nowIso();
      for (const raw of items) {
        const id = raw.id || newId("txn");
        insertStmt.run(
          id,
          raw.userId || userId || null,
          raw.date,
          raw.description || "Lancamento",
          raw.payerName || null,
          raw.beneficiaryName || null,
          Number(raw.amount || 0),
          raw.type || "INCOME",
          raw.category || "Outros",
          raw.method || "PIX",
          raw.status || "PAID",
          raw.receiptStatus || null,
          JSON.stringify(Array.isArray(raw.tags) ? raw.tags : []),
          raw.isRecurring ? 1 : 0,
          raw.payerCpf || null,
          raw.beneficiaryCpf || null,
          raw.observation || null,
          now,
          now
        );
      }
    });

    const userId = req.body.userId || null;
    insertMany(parsed.transactions, userId);

    res.status(201).json({
      imported: parsed.transactions.length,
      ignored: parsed.errors,
      message: "Import completed",
    });
  } finally {
    removeTmpFile(req.file);
  }
});

router.get("/transactions/export", (req, res) => {
  const format = String(req.query.format || "csv").toLowerCase();
  const userId = req.query.userId;

  const rows = userId
    ? db.prepare("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC").all(userId)
    : db.prepare("SELECT * FROM transactions ORDER BY date DESC").all();

  const items = rows.map(toTransaction);

  if (format === "json") {
    return res.json(items);
  }

  if (format === "xlsx") {
    const ws = XLSX.utils.json_to_sheet(items);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "transactions");

    const buffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename=transactions-${Date.now()}.xlsx`);
    return res.send(buffer);
  }

  const headers = [
    "id",
    "userId",
    "date",
    "description",
    "payerName",
    "beneficiaryName",
    "amount",
    "type",
    "category",
    "method",
    "status",
    "receiptStatus",
    "tags",
    "isRecurring",
    "payerCpf",
    "beneficiaryCpf",
    "observation",
    "createdAt",
    "updatedAt",
  ];

  const lines = [headers.join(";")];
  for (const item of items) {
    const line = headers
      .map((h) => {
        const raw = item[h];
        const value = Array.isArray(raw) ? raw.join("|") : raw ?? "";
        return `"${String(value).replace(/"/g, '""')}"`;
      })
      .join(";");
    lines.push(line);
  }

  const csv = lines.join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename=transactions-${Date.now()}.csv`);
  res.send(`\uFEFF${csv}`);
});

router.get("/dashboard/summary", (req, res) => {
  const summary = calcSummary(req.query.userId);
  res.json(summary);
});

router.get("/dashboard/charts", (req, res) => {
  const userId = req.query.userId;
  const where = userId ? "WHERE user_id = ?" : "";
  const args = userId ? [userId] : [];

  const categoryRows = db
    .prepare(`
      SELECT category AS name, SUM(amount) AS value
      FROM transactions
      ${where} ${where ? "AND" : "WHERE"} type = 'INCOME'
      GROUP BY category
      ORDER BY value DESC
    `)
    .all(...args);

  const methodRows = db
    .prepare(`
      SELECT method AS name, SUM(amount) AS value
      FROM transactions
      ${where} ${where ? "AND" : "WHERE"} type = 'INCOME'
      GROUP BY method
      ORDER BY value DESC
    `)
    .all(...args);

  const pendingReceiptsRow = db
    .prepare(`
      SELECT COUNT(*) AS value
      FROM transactions
      ${where} ${where ? "AND" : "WHERE"} type = 'INCOME' AND receipt_status = 'PENDING'
    `)
    .get(...args);

  res.json({
    categoryData: categoryRows.map((r) => ({ name: r.name, value: Number(r.value || 0) })),
    methodData: methodRows.map((r) => ({ name: r.name, value: Number(r.value || 0) })),
    pendingReceipts: Number(pendingReceiptsRow.value || 0),
  });
});

router.get("/reports/dre", (req, res) => {
  const userId = req.query.userId;
  const summary = calcSummary(userId);

  const where = userId ? "WHERE user_id = ?" : "";
  const args = userId ? [userId] : [];

  const incomeCountRow = db
    .prepare(`SELECT COUNT(*) AS value FROM transactions ${where} ${where ? "AND" : "WHERE"} type = 'INCOME'`)
    .get(...args);

  const overdueRow = db
    .prepare(
      `SELECT COALESCE(SUM(amount),0) AS value FROM transactions ${where} ${where ? "AND" : "WHERE"} type = 'INCOME' AND status = 'OVERDUE'`
    )
    .get(...args);

  const fixedExpenseRow = db
    .prepare(
      `SELECT COALESCE(SUM(amount),0) AS value FROM transactions ${where} ${where ? "AND" : "WHERE"} type = 'EXPENSE' AND LOWER(tags) LIKE '%fixa%'`
    )
    .get(...args);

  const incomeCount = Number(incomeCountRow.value || 0);
  const ticketMedio = incomeCount > 0 ? summary.totalIncome / incomeCount : 0;
  const inadimplencia = Number(overdueRow.value || 0);
  const fixasVariaveisPerc = summary.totalExpense > 0 ? (Number(fixedExpenseRow.value || 0) / summary.totalExpense) * 100 : 0;

  res.json({
    month: new Date().toISOString().slice(0, 7),
    summary,
    indicators: {
      ticketMedio,
      inadimplencia,
      fixasVariaveisPerc,
      projectedNextMonth: summary.liquidResult,
    },
  });
});

app.use(API_PREFIX, router);

app.use((err, req, res, next) => {
  if (err && err.message === "Origin not allowed by CORS") {
    return res.status(403).json({ message: err.message });
  }

  if (err && err.code === "SQLITE_CONSTRAINT_UNIQUE") {
    return res.status(409).json({ message: "Unique constraint violation" });
  }

  console.error(err);
  res.status(500).json({ message: "Internal server error" });
});

function startServer(port) {
  app.listen(port, () => {
    console.log(`PsiGestao API running on http://localhost:${port}${API_PREFIX}`);
  }).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`Porta ${port} em uso. Tentando próxima porta...`);
      startServer(port + 1);
    } else {
      throw err;
    }
  });
}
startServer(PORT);


