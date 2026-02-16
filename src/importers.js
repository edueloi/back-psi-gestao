const TransactionType = {
  INCOME: "INCOME",
  EXPENSE: "EXPENSE",
};

const PaymentMethod = {
  PIX: "PIX",
  CARD: "CARD",
  CASH: "CASH",
  TRANSFER: "TRANSFER",
};

const ReceiptStatus = {
  PENDING: "PENDING",
};

const TransactionStatus = {
  PAID: "PAID",
};

function parseCurrency(value) {
  if (value == null) return 0;
  const str = String(value).trim();
  if (!str || str === "-") return 0;

  let clean = str.replace(/R\$/gi, "").replace(/\$/g, "").replace(/\s/g, "").trim();

  if (clean.includes(",") && clean.includes(".")) {
    clean = clean.replace(/\./g, "").replace(",", ".");
  } else if (clean.includes(",")) {
    clean = clean.replace(",", ".");
  }

  const parsed = Number.parseFloat(clean);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function parseBrDate(value) {
  if (!value) return "";
  const sanitized = String(value).trim().replace(/\/\//g, "/");
  const parts = sanitized.split("/");
  if (parts.length !== 3) return "";

  let day = parts[0].padStart(2, "0");
  let month = parts[1].padStart(2, "0");
  let year = parts[2];
  if (year.length === 2) year = `20${year}`;

  if (!/^\d{2}$/.test(day) || !/^\d{2}$/.test(month) || !/^\d{4}$/.test(year)) return "";
  return `${year}-${month}-${day}`;
}

function extractBeneficiaryInfo(observation, payerName, payerCpf) {
  if (!observation) {
    return { name: payerName, cpf: payerCpf };
  }

  const regex = /(?:Beneficiario|Beneficiario|Paciente):\s*([^C\d\n\r,]+)(?:\s*CPF\s*([\d.\-]+))?/i;
  const match = String(observation).match(regex);

  if (match) {
    return {
      name: (match[1] || payerName || "").trim(),
      cpf: (match[2] || payerCpf || "").trim(),
    };
  }

  return { name: payerName, cpf: payerCpf };
}

function rowToTransaction(cols, index) {
  if (!Array.isArray(cols) || cols.length < 3) return null;

  const dateStr = String(cols[0] || "").trim();
  if (!dateStr || dateStr.toLowerCase().includes("data")) return null;

  const date = parseBrDate(dateStr);
  if (!date) return null;

  const format = String(cols[1] || "").toLowerCase();
  const payerName = String(cols[2] || "Desconhecido").trim() || "Desconhecido";
  const payerCpf = String(cols[3] || "").trim();

  const incomeVal = parseCurrency(cols[4]);
  const expenseVal = parseCurrency(cols[6] || 0);

  const isIncome = incomeVal > 0 || format.includes("recebido");
  const amount = isIncome ? incomeVal : expenseVal;
  if (!amount) return null;

  const observation = String(cols[8] || "");
  const beneficiary = extractBeneficiaryInfo(observation, payerName, payerCpf);

  let category = isIncome ? "Sessao Individual" : "Outros";
  if (isIncome) {
    if (amount >= 360) category = "Pacote Semanal";
    else if (amount >= 200) category = "Sessao Individual";
    else if (amount <= 100) category = "Sessao Mensal";
  }

  return {
    date,
    description: isIncome ? "Psicoterapia Individual" : "Despesa",
    payerName,
    beneficiaryName: beneficiary.name,
    amount,
    type: isIncome ? TransactionType.INCOME : TransactionType.EXPENSE,
    category,
    method: format.includes("pix") ? PaymentMethod.PIX : PaymentMethod.TRANSFER,
    status: TransactionStatus.PAID,
    receiptStatus: ReceiptStatus.PENDING,
    payerCpf,
    beneficiaryCpf: beneficiary.cpf,
    observation,
    tags: isIncome ? ["Particular"] : [],
    idHint: `${Date.now()}-${index}`,
  };
}

function parseImportedText(text) {
  const lines = String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim() !== "");

  let errors = 0;
  const transactions = [];

  lines.forEach((line, index) => {
    const cols = line.includes("\t") ? line.split("\t") : line.split(";");
    const parsed = rowToTransaction(cols, index);
    if (parsed) transactions.push(parsed);
    else errors += 1;
  });

  return { transactions, errors };
}

function parseImportedRows(rows) {
  let errors = 0;
  const transactions = [];

  rows.forEach((row, index) => {
    const parsed = rowToTransaction(row, index);
    if (parsed) transactions.push(parsed);
    else errors += 1;
  });

  return { transactions, errors };
}

module.exports = {
  parseImportedText,
  parseImportedRows,
};
