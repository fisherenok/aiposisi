const keys = require('../keys')

module.exports = function (email, token) {
    return {
        to: email,
        from: keys.EMAIL_FROM,
        subject: 'Восстановление пароля к SHOP COURSES',
        html: `
            <h1>Добро пожаловать в наш магазин</h1>
            <p>Вы отправили заявку на восстановление данных к аккаунту с email: ${email}</p><br />
            <p>Если вы не отправляли заявок, то проигнорируйте это сообщение</p>
            <p><a href="${keys.BASE_URL}/auth/password/${token}">Восстановление пароля(клик)</a></p>
            <hr />
            <a href="${keys.BASE_URL}">Магазин курсов</a>
        `
    }
}