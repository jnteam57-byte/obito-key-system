const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

const DB_FILE = path.join(__dirname, "keys.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function readKeys() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, "[]");
    }

    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function saveKeys(keys) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify(keys, null, 2)
    );
}

function generateKey() {
    const random = crypto
        .randomBytes(6)
        .toString("hex")
        .toUpperCase();

    return `OBITO-${random.slice(0,4)}-${random.slice(4,8)}-${random.slice(8,12)}`;
}

function adminOnly(req, res, next) {

    const auth = req.headers.authorization;

    if (!ADMIN_TOKEN) {
        return res.status(500).json({
            ok: false,
            error: "ADMIN_TOKEN não configurado"
        });
    }

    if (auth !== `Bearer ${ADMIN_TOKEN}`) {
        return res.status(401).json({
            ok: false,
            error: "Não autorizado"
        });
    }

    next();
}


// LOGIN
app.post("/api/login", (req, res) => {

    const key = String(req.body.key || "")
        .trim()
        .toUpperCase();

    const keys = readKeys();

    const item = keys.find(k => k.key === key);

    if (!item) {
        return res.status(404).json({
            ok: false,
            error: "Key inválida"
        });
    }

    if (item.revoked) {
        return res.status(403).json({
            ok: false,
            error: "Key revogada"
        });
    }

    if (Date.now() >= item.expiresAt) {
        return res.status(403).json({
            ok: false,
            error: "Key expirada"
        });
    }

    res.json({
        ok: true,
        expiresAt: item.expiresAt
    });
});


// LISTAR KEYS
app.get("/api/admin/keys", adminOnly, (req, res) => {

    res.json(readKeys());

});


// CRIAR KEY
app.post("/api/admin/keys", adminOnly, (req, res) => {

    const days = Math.max(
        1,
        Math.min(
            3650,
            Number(req.body.days || 30)
        )
    );

    const now = Date.now();

    const key = {
        key: generateKey(),
        createdAt: now,
        expiresAt: now + days * 86400000,
        revoked: false
    };

    const keys = readKeys();

    keys.push(key);

    saveKeys(keys);

    res.json({
        ok: true,
        ...key
    });
});


// REVOGAR KEY
app.post("/api/admin/revoke", adminOnly, (req, res) => {

    const key = String(req.body.key || "")
        .trim()
        .toUpperCase();

    const keys = readKeys();

    const item = keys.find(k => k.key === key);

    if (!item) {
        return res.status(404).json({
            ok: false,
            error: "Key não encontrada"
        });
    }

    item.revoked = true;
    item.revokedAt = Date.now();

    saveKeys(keys);

    res.json({
        ok: true
    });
});


app.listen(PORT, () => {

    console.log(
        `OBITO KEY SERVER rodando na porta ${PORT}`
    );

});
