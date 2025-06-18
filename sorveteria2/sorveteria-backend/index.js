const express = require("express");
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require('multer');
const path = require('path');

const cors = require("cors");
app.use(cors());
app.use('/uploads', express.static('uploads'));


const app = express();
app.use(express.json());
app.use('/uploads', express.static('uploads'));



// Configuração da conexão com o banco
const db = mysql.createConnection = ({
    host: "localhost",
    user: "root",
    password: "PUC@1234",
    database: "sorveteria_db"
});

async function getConnection() {
    return await mysql.createConnection(dbConfig);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });


// Middleware para validar o token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Token não fornecido" });

    jwt.verify(token, "secreto_do_jwt", (err, user) => {
        if (err) return res.status(403).json({ message: "Token inválido" });
        req.user = user;
        next();
    });
}

// ✅ Cadastro de usuário (admin)
app.post('/api/usuarios', async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.status(400).json({ message: 'Preencha todos os campos' });
    }

    const hashSenha = await bcrypt.hash(senha, 10);

    db.query('INSERT INTO usuarios (nome, email, senha, criado_em, admin) VALUES (?, ?, ?, NOW(), 0)',
        [nome, email, hashSenha],
        (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Erro ao cadastrar usuário' });
            }
            res.json({ message: 'Usuário cadastrado com sucesso!' });
        });
});

// Listar usuários
app.get('/api/usuarios', (req, res) => {
    db.query('SELECT id, nome, email, criado_em, admin FROM usuarios', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Erro ao buscar usuários' });
        }
        res.json(results);
    });
});
// ✅ Login com JWT
app.post("/api/login", (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ message: "Preencha email e senha" });
    }

    const sql = "SELECT * FROM usuarios WHERE email = ?";
    db.query(sql, [email], (err, result) => {
        if (err || result.length === 0) {
            return res.status(401).json({ message: "Usuário não encontrado" });
        }

        const usuario = result[0];
        if (usuario.senha !== senha) {
            return res.status(401).json({ message: "Senha incorreta" });
        }

        // 🔐 Aqui é onde você inclui "admin" no payload
        const token = jwt.sign(
            {
                id: usuario.id,
                email: usuario.email,
                admin: usuario.admin, // <- isso assume que sua tabela "usuarios" tem a coluna "admin"
            },
            secret,
            { expiresIn: "1h" }
        );

        res.json({ token });
    });
});


app.listen(3001, () => console.log("Servidor rodando na porta 3001"));

// CREATE - Adiciona um novo produto (Requer autenticação)
app.post("/produtos", authenticateToken, async (req, res) => {
    const { nome, sabor, preco, quantidade } = req.body;
    if (!nome || !sabor || !preco || !quantidade) {
        return res.status(400).json({ message: "Preencha todos os campos" });
    }
    try {
        const conn = await getConnection();
        await conn.execute(
            "INSERT INTO produtos (nome, sabor, preco, quantidade) VALUES (?, ?, ?, ?)",
            [nome, sabor, preco, quantidade]
        );
        await conn.end();
        res.status(201).json({ message: "Produto cadastrado com sucesso" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao cadastrar produto" });
    }
});

// READ - Listar todos os produtos
app.get("/produtos", async (req, res) => {
    try {
        const conn = await getConnection();
        const [produtos] = await conn.execute("SELECT * FROM produtos");
        await conn.end();
        res.json(produtos);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao listar produtos" });
    }
});

// UPDATE - Editar um produto por ID (Requer autenticação)
app.put("/produtos/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { nome, sabor, preco, quantidade } = req.body;
    try {
        const conn = await getConnection();
        await conn.execute(
            "UPDATE produtos SET nome=?, sabor=?, preco=?, quantidade=? WHERE id=?",
            [nome, sabor, preco, quantidade, id]
        );
        await conn.end();
        res.json({ message: "Produto atualizado com sucesso" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao atualizar produto" });
    }
});

// - Remover um produto (Requer autenticação)
app.delete("/produtos/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const conn = await getConnection();
        await conn.execute("DELETE FROM produtos WHERE id = ?", [id]);
        await conn.end();
        res.json({ message: "Produto removido com sucesso" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao excluir produto" });
    }
});

// POST - Realizar venda de um produto
app.post("/vendas", authenticateToken, async (req, res) => {
    const { produto_id, quantidade } = req.body;
    if (!produto_id || !quantidade) {
        return res.status(400).json({ message: "Informe o produto e a quantidade" });
    }

    try {
        const conn = await getConnection();

        // Verifica se o produto existe e tem estoque
        const [prod] = await conn.execute("SELECT * FROM produtos WHERE id = ?", [produto_id]);
        if (prod.length === 0) {
            await conn.end();
            return res.status(404).json({ message: "Produto não encontrado" });
        }

        const produto = prod[0];
        if (produto.quantidade < quantidade) {
            await conn.end();
            return res.status(400).json({ message: "Estoque insuficiente" });
        }

        const total = produto.preco * quantidade;

        // Cadastra a venda
        await conn.execute(
            "INSERT INTO vendas (produto_id, quantidade, total) VALUES (?, ?, ?)",
            [produto_id, quantidade, total]
        );

        // Atualiza o estoque do produto
        const novoEstoque = produto.quantidade - quantidade;
        await conn.execute("UPDATE produtos SET quantidade = ? WHERE id = ?", [
            novoEstoque,
            produto_id,
        ]);

        await conn.end();
        res.status(201).json({ message: "Venda realizada com sucesso", total });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao realizar venda" });
    }
});

app.get("/vendas", authenticateToken, async (req, res) => {
    try {
        const conn = await getConnection();
        const [vendas] = await conn.execute(`
      SELECT v.id, p.nome, v.quantidade, v.total, v.data_venda
      FROM vendas v
      JOIN produtos p ON v.produto_id = p.id
    `);
        await conn.end();
        res.json(vendas);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao listar vendas" });
    }
});

// Rota para cadastrar um novo usuário (admin)
app.post('/api/cadastro', async (req, res) => {
    const { nome, email, password } = req.body;

    if (!nome || !email || !password) {
        return res.status(400).json({ message: "Preencha todos os campos!" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)';
        await db.query(sql, [nome, email, hashedPassword]);
        res.status(201).json({ message: "Usuário cadastrado com sucesso!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erro ao cadastrar usuário." });
    }
});

// Sorvetes CRUD
app.post('/api/sorvetes', upload.single('foto'), (req, res) => {
    const { sabor, preco, descricao } = req.body;
    const foto = req.file ? req.file.filename : null;

    db.query('INSERT INTO sorvetes (sabor, preco, descricao, foto) VALUES (?, ?, ?, ?)',
        [sabor, preco, descricao, foto],
        (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Erro ao cadastrar sorvete');
            }
            res.json({ message: 'Sorvete cadastrado com sucesso!' });
        });
});

// Listar sorvetes
app.get('/api/sorvetes', (req, res) => {
    db.query('SELECT * FROM sorvetes', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Erro ao buscar sorvetes');
        }
        res.json(results);
    });
});

app.put("/sorvetes/:id", (req, res) => {
    const { sabor, preco, descricao } = req.body;
    const sql = "UPDATE sorvetes SET sabor = ?, preco = ?, descricao = ? WHERE id = ?";
    db.query(sql, [sabor, preco, descricao, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: "Erro ao atualizar sorvete" });
        res.json({ message: "Sorvete atualizado com sucesso!" });
    });
});

app.delete("/sorvetes/:id", (req, res) => {
    db.query("DELETE FROM sorvetes WHERE id = ?", [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: "Erro ao deletar sorvete" });
        res.json({ message: "Sorvete excluído com sucesso!" });
    });
});

app.post('/vendas', async (req, res) => {
    const { fk_id_sorvete, fk_id_usuario } = req.body;

    try {
        await db.query(
            'INSERT INTO vendas (fk_id_sorvete, fk_id_usuario, horario) VALUES (?, ?, NOW())',
            [fk_id_sorvete, fk_id_usuario]
        );

        res.send({ message: 'Venda registrada com sucesso!' });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Erro ao registrar venda.' });
    }
});