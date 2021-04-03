const passport = require('passport');
const LocalStrategy = require('passport-local');

const Usuario = require('./usuarios-modelo');
const {InvalidArgumentError} = require('../erros');

const bcrypt = require('bcrypt');

function verificaUsuario (usuario){
    if(!usuario){
        throw new InvalidArgumentError('Não existe usuário com esse email');
    }
}

async function verificarSenha(senha, senhaHash){
    const senhaValida = await bcrypt.compare(senha, senhaHash);
    if(!senhaValida){
        throw new InvalidArgumentError('Email ou senha inválidos');
    }
}

passport.use(
    new LocalStrategy({
        usernameField: 'email',
        passwordFiled: 'senha',
        session: false
    }, async (email, senha, done) =>{
        try {

            const usuario = await Usuario.buscaPorEmail(email);
            verificaUsuario(usuario);
            await verificarSenha(senha, usuario.senhaHash);

            done(null, usuario);

        } catch (error) {
            done(error);
        }
        
    })
);