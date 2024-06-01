const express = require('express');
const path = require('path');
const app = express();
const router = express.Router();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const users = {};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.json());

// Rota raiz 
router.get('/', function (req, res) {
    res.redirect('/login');
});

// Rota para a página de login
router.get('/login', function (req, res) {
    res.sendFile(path.join(__dirname, '/index.html'));
});

// Rota para a página de registro
router.get('/pages/registro.html', function (req, res) {
    res.sendFile(path.join(__dirname, '/pages/registro.html'));
});

// Rota para a página de troca de senha
router.get('/pages/request-password-reset.html', function (req, res) {
    res.sendFile(path.join(__dirname, '/pages/request-password-reset.html'));
});

// Rota para solicitar a troca de senha
app.post('/request-password-reset', (req, res) => {
    const { username } = req.body;
    const user = users[username];
  
    if (!user) {
      return res.status(400).send('Usuário não encontrado');
    }
  
    const token = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000;
  
    users[username] = user; 

    console.log(`Token gerado para o usuário ${username}: ${token}`);
  
    // Enviar link de troca de senha
    res.send(`Use este link para redefinir sua senha: <a href="http://${req.headers.host}/reset-password/${token}">Redefinir Senha</a>`);
  });

// Rota para exibir o form de troca de senha
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const userKeys = Object.keys(users);
    const user = userKeys.map(key => users[key]).find(user => user.resetPasswordToken === token && user.resetPasswordExpires > Date.now());
  
    if (!user) {
        console.log('Token inválido ou expirado:', token);
        return res.status(400).send('Token de redefinição de senha é inválido ou expirou.');
    }
  
    // Enviar formulário HTML com o token embutido
    console.log(`Token válido, entregando formulário: ${token}`);
    res.send(`
        <form action="/reset-password" method="post">
        <input type="hidden" name="token" value="${token}" />
        <label for="password">Nova Senha:</label>
        <input type="password" id="password" name="password" required />
        <label for="confirmPassword">Confirme a Nova Senha:</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required />
        <button type="submit">Redefinir Senha</button>
        </form>
    `);
  });

// Rota para executar a redefinição de senha
app.post('/reset-password', async (req, res) => {
    const { token, password, confirmPassword } = req.body;
  
    if (password !== confirmPassword) {
        return res.status(400).send('As senhas não coincidem.');
    }
  
    const userKeys = Object.keys(users);
    const user = userKeys.map(key => users[key]).find(user => user.resetPasswordToken === token && user.resetPasswordExpires > Date.now());
  
    if (!user) {
        console.log('Tentativa de redefinição falhou. Token inválido ou expirado:', token);
        return res.status(400).send('Token de redefinição de senha é inválido ou expirou.');
    }
  
    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
  
    users[user.username] = user; 
  
    res.redirect('/login');
  });

// Rota de registro
router.post('/register', async function (req, res) {
    const { username, password } = req.body;

    console.log('Recebido username:', username);
    console.log('Recebido password:', password);

    if (!username || !password) {
        return res.status(400).send('Username e password são obrigatórios');
    }

    if (users[username]) {
        return res.status(400).send('Usuário já existe');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users[username] = { password: hashedPassword };

        console.log('Usuário registrado:', username);

        res.redirect('/login');
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).send('Erro interno do servidor');
    }
});

// Rota de login
router.post('/login', async function (req, res) {
    const { username, password } = req.body;

    console.log('Tentativa de login username:', username);
    console.log('Tentativa de login password:', password);

    if (!username || !password) {
        return res.status(400).send('Username e password são obrigatórios');
    }

    const user = users[username];
    if (!user) {
        return res.status(400).send('Usuário não encontrado');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).send('Senha incorreta');
    }

    res.redirect('/home');
});

// Rota para  a página de venda de carros
app.get('/sellcar', function(req, res) {
    res.sendFile(path.join(__dirname, '/pages/sellCars.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

app.use('/styles', express.static(path.join(__dirname, 'public/styles')));

app.use('/styles', express.static(path.join(__dirname, 'public/styles')));

app.use('/scripts', express.static(path.join(__dirname, 'public/scripts')));

app.use('/', router);

// Rota para a home page
router.get('/home', function (req, res) {
    res.sendFile(path.join(__dirname, '/pages/home.html'));
});

// Rota de logout
router.get('/logout', function (req, res) {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).send('Erro ao fazer logout');
            }
            res.redirect('/');
        });
    } else {
        res.redirect('/');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
    console.log(`Servidor rodando na porta ${PORT}`);
});