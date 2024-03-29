const passport = require('passport');
const usuariosControlador = require('./usuarios-controlador');

module.exports = app => {
app
.route('usuario/login')
.post(passport.authenticate('local', {session: false}), usuariosControlador.login)

  app
    .route('/usuario')
    .post(usuariosControlador.adiciona)
    .get(usuariosControlador.lista);

  app.route('/usuario/:id').delete(usuariosControlador.deleta);
};
