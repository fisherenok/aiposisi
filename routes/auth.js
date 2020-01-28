const {Router} = require('express')
const User = require('../models/user')
const nodemailer = require('nodemailer')
const sendgrid = require('nodemailer-sendgrid-transport')
const keys = require('../keys')
const {validationResult} = require('express-validator/check')
const regEmail = require('../emails/registration')
const resetEmail = require('../emails/reset')
const crypto = require('crypto')
const bcrypt = require('bcryptjs')
const router = Router()
const {registerValidators, loginValidators, resetValidators} = require('../utils/validator')


const transporter = nodemailer.createTransport(sendgrid({
    auth: {api_key: keys.SENDGRIDS_API_KEY}
}))

router.get('/login', async (req, res) => {
    res.render('auth/login', {
        title: 'Авторизация',
        isLogin: true,
        registerError: req.flash('registerError'),
        loginError: req.flash('loginError'),
    })
})

router.get('/logout', async (req, res) => {
    req.session.destroy(() => {
        res.redirect('/auth/login#login')
    })
})

router.post('/login', loginValidators, async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            req.flash('loginError', errors.array()[0].msg)
            return res.status(422).redirect('/auth/login#login')
        }
        const candidate = await User.findOne({email: req.body.email})
        req.session.user = candidate
        req.session.isAuthenticated = true
        req.session.save(err => {
            if (err) throw err
            res.redirect('/')
        })
    } catch (e) {
        console.log(e)
    }
})

router.post('/register', registerValidators, async (req, res) => {
    try {
        const {email, password, name} = req.body

        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            req.flash('registerError', errors.array()[0].msg)
            return res.status(422).redirect('/auth/login#register')
        }

        const hashPassword = await bcrypt.hash(password, 10)
        const user = new User({
            email, name, password: hashPassword, cart: {items: []}
        })
        await user.save()
        await transporter.sendMail(regEmail(email))
        res.redirect('/auth/login#login')
    } catch (e) {
        console.log(e)
    }
})

router.get('/reset', (req, res) => {
    res.render('auth/reset', {
        title: 'Забыли пароль',
        error: req.flash('error')
    })
})

router.post('/reset', resetValidators, (req, res) => {

    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        req.flash('error', errors.array()[0].msg)
        return res.status(422).redirect('/auth/reset')
    }

    try {
        crypto.randomBytes(32, async (err, buffer) => {
            if (err) {
                req.flash('error', 'Что-то пошло не так повтороите попытку позже.')
                return res.redirect('/auth/reset')
            }

            const token = buffer.toString('hex')
            const candidate = await User.findOne({email: req.body.email})

            candidate.resetToken = token
            candidate.resetTokenExp = Date.now() + 60 * 60 * 1000 //1 hours
            await candidate.save()
            await transporter.sendMail(resetEmail(candidate.email, token))
            res.redirect('/auth/login')
        })
    } catch (e) {
        console.log(e)
    }
})

router.get('/password/:token', async (req, res) => {
    if (!req.params.token) {
        return res.redirect('/auth/login')
    }

    try {
        const user = await User.findOne({
            resetToken: req.params.token,
            resetTokenExp: {$gt: Date.now()}
        })

        if (!user) {
            return res.redirect('/auth/login')
        } else {
            res.render('auth/password', {
                title: 'Восстановить доступ',
                error: req.flash('error'),
                userId: user._id.toString(),
                token: req.params.token
            })
        }
    } catch (e) {
        console.log(e)
    }
})

router.post('/password', async (req, res) => {
    try {
        const user = await User.findOne({
            _id: req.body.userId,
            resetToken: req.body.token,
            resetTokenExp: {$gt: Date.now()}
        })

        if (req.body.password !== req.body.passwordTwo) {
            req.flash('error', 'Пароли не совпадают.')
            return res.redirect(`/auth/password/${req.body.token}`)
        }

        if (user) {
            user.password = await bcrypt.hash(req.body.password, 10)
            user.resetToken = undefined
            user. resetTokenExp = undefined
            await user.save()
            res.redirect('/auth/login')
        } else {
            req.flash('loginError', 'Время на восстановление истекло')
            return res.redirect('/auth/login')

        }
    } catch (e) {
        console.log(e)
    }
})

module.exports = router