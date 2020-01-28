const {body, validationResult} = require('express-validator/check')
const User = require('../models/user')
const bcrypt = require('bcryptjs')

exports.registerValidators = [
    body('email')
        .isEmail()
        .withMessage('Введите корректный Email')
        .custom(async (value) => {
        try {
            const candidate = await User.findOne({email: value})
            if (candidate) {
                return Promise.reject('Такой email уже занят')
            }
        } catch (e) {
            console.log(e)
        }
    }).normalizeEmail(),

    body('password', 'Пароль должен быть минимум 8 символов и состоять из букв и цифр')
        .isLength({min: 8, max: 16})
        .isAlphanumeric()
        .trim(),

    body('confirm')
        .custom((value, {req}) => {
        if (value !== req.body.password) {
            throw new Error('Пароли не совпадают')
        }
        return true
    }).trim(),

    body('name', 'Имя должно быть минимум 3 символа')
        .isLength({min: 3})
        .trim()
]

exports.loginValidators = [
    body('email')
        .isEmail()
        .withMessage('Введите корректный Email')
        .custom(async (value, {req}) => {
            try {
                const candidate = await User.findOne({email: req.body.email})
                if (!candidate) {
                    return Promise.reject('Такой email отсутствует')
                }
            } catch (e) {
                console.log(e)
            }
        }).normalizeEmail(),

    body('password', 'Пароль должен быть минимум 8 символов и состоять из букв и цифр')
        .isLength({min: 8, max: 16})
        .isAlphanumeric()
        .custom(async (value, {req}) => {
            try {
                const candidate = await User.findOne({email: req.body.email})
                const areSame = await bcrypt.compare(req.body.password, candidate.password)
                if (!areSame) {
                    return Promise.reject('Неверный пароль')
                }
            } catch (e) {
                console.log(e)
            }
        })
        .trim(),
] //дописать

exports.resetValidators = [
    body('email')
        .isEmail()
        .withMessage('Введите корректный Email')
        .custom(async (value, {req}) => {
            try {
                console.log(value)
                const candidate = await User.findOne({email: value})
                if (!candidate) {
                    return Promise.reject('Такой email отсутствует')
                }
            } catch (e) {
                console.log(e)
            }
        }).normalizeEmail(),
] //дописать

exports.passwordValidators = [] //дописать

exports.courseValidators = [
    body('title')
        .isLength({min: 3})
        .withMessage('Минимальный размер названия 3 символа')
        .trim(),

    body('price')
        .isNumeric()
        .withMessage('Введите корректную цену'),

    body('img', 'Введите корректный URL картинки')
        .isURL()
]
