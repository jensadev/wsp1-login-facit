const express = require('express');
const router = express.Router();
const pool = require('../utils/database');
const { authBySession } = require('../middleware/auth');
const bcrypt = require('bcrypt');

/* GET home page. */
router.get('/', function (req, res, next) {
    res.render('index.njk', { title: 'Login ALC' });
});

router.get('/login', function (req, res, next) {
    if (req.session.uid && req.session.username) {
        res.redirect('/profile');
    }
    res.render('login.njk', { title: 'Login' });
});

router.post('/login', async function (req, res, next) {
    try {
        const { username, password } = req.body;
        if (!username) throw new Error('Username is Required');
        if (!password) throw new Error('Password is Required');

        const [rows] = await pool
            .promise()
            .query(`SELECT id, password FROM users WHERE name = ? LIMIT 1`, [
                username,
            ]);

        const result = rows[0];

        if (!result) throw new Error('User not found');
        const match = await bcrypt.compare(password, result.password);
        if (!match) throw new Error('Invalid username or password');

        req.session.uid = result.id;
        req.session.username = username;
        res.redirect('/profile');
    } catch (error) {
        res.render('login.njk', { title: 'Login', error: error.message });
    }
});

router.get('/profile', authBySession, function (req, res) {
    return res.render('profile.njk', { title: 'Profile', username: req.session.username });
});

router.post('/logout', authBySession, function (req, res) {
    req.session.destroy();
    res.redirect('/');
});

router.get('/register', function (req, res) {
    res.render('register.njk', { title: 'Register' });
});

router.post('/register', async function (req, res) {
    try {
        const { username, password, passwordConfirmation } = req.body;
        if (!username) throw new Error('Username is Required');
        if (!password) throw new Error('Password is Required');
        if (password !== passwordConfirmation) throw new Error('Passwords do not match');

        let [rows] = await pool
            .promise()
            .query(`SELECT name FROM users WHERE name = ? LIMIT 1`, [
                username,
            ]);

        const user = rows[0];

        if (user) throw new Error('Username is already taken');

        const hash = await bcrypt.hash(password, 10);

        [rows] = await pool
        .promise()
        .query(`INSERT INTO users (name, password) VALUES (?,?)`, [
            username,
            hash,
        ]);

        if (rows.affectedRows === 0) throw new Error('User not created');
        res.redirect('/login');
    } catch (error) {
        res.render('register.njk', { title: 'Register', error: error.message });
    }
});

module.exports = router;
