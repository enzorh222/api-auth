'use strict'

// importaciones
const config = require('./config');
const express = require('express');
const logger = require('morgan');
const mongojs = require('mongojs');
const cors = require('cors');
const helmet = require('helmet');
const fs = require('fs');
const https = require('https');
const moment = require('moment');
const TokenHelper = require('./helpers/token.helper');
const PassHelper = require('./helpers/pass.helper');
const AuthMiddleware = require('./middlewares/auth.middleware');

// Declaraciones
const port = config.PORT;
const urlDB = config.DB;

const app = express();

const db = mongojs(urlDB);
const id = mongojs.ObjectID;

// Declaraciones para CORS
var allowCrossTokenOrigin = (req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    return next();
};

var allowCrossTokenMethods = (req, res, next) => {
    res.header("Access-Control-Allow-Methods", "*");
    return next();
};

var allowCrossTokenHeaders = (req, res, next) => {
    res.header("Access-Control-Allow-Headers", "*");
    return next();
};

// Middlewares
app.use(helmet());
app.use(logger('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());
app.use(allowCrossTokenOrigin);
app.use(allowCrossTokenMethods);
app.use(allowCrossTokenHeaders);

// routes /api/user
app.get('/api/user', AuthMiddleware.auth, (req, res, next) => {
    db.user.find((err, coleccion) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(coleccion);
    });
});

app.get('/api/user/:id', AuthMiddleware.auth, (req, res, next) => {
    const elementoId = req.params.id;
    db.user.findOne({ _id: id(elementoId) }, (err, elementoRecuperado) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(elementoRecuperado);
    });
});

app.post('/api/user', AuthMiddleware.auth, (req, res, next) => {
    const nuevoElemento = req.body;
    db.user.save(nuevoElemento, (err, coleccionGuardada) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(coleccionGuardada);
    });
});

app.put('/api/user/:id', AuthMiddleware.auth, (req, res, next) => {
    const elementoId = req.params.id;
    const nuevosRegistros = req.body;
    db.user.update(
        { _id: id(elementoId) },
        { $set: nuevosRegistros },
        { safe: true, multi: false },
        (err, result) => {
            if (err) return res.status(500).json({ result: 'KO', msg: err });
            res.json(result);
        });
});

app.delete('/api/user/:id', AuthMiddleware.auth, (req, res, next) => {
    const elementoId = req.params.id;
    db.user.remove({ _id: id(elementoId) }, (err, resultado) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(resultado);
    });
});

// routes /api/auth
app.get('/api/auth', AuthMiddleware.auth, (req, res, next) => {
    db.user.find({}, { _id: 0, displayName: 1, email: 1 }, (err, usuarios) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json({ result: 'OK', usuarios: usuarios });
    });
});

app.get('/api/auth/me', AuthMiddleware.auth, (req, res, next) => {
    db.user.findOne({ _id: id(req.user.id) }, (err, usuario) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        if (!usuario) return res.status(404).json({ result: 'KO', msg: 'Usuario no encontrado' });
        res.json({ result: 'OK', usuario: usuario });
    });
});

app.post('/api/auth/reg', (req, res, next) => {
    const { name, email, pass } = req.body;

    if (!name) return res.status(400).json({ result: 'KO', msg: 'El nombre es obligatorio' });
    if (!email) return res.status(400).json({ result: 'KO', msg: 'El email es obligatorio' });
    if (!pass) return res.status(400).json({ result: 'KO', msg: 'La contraseña es obligatoria' });

    db.user.findOne({ email: email }, (err, usuarioExistente) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        if (usuarioExistente) return res.status(400).json({ result: 'KO', msg: 'Ya existe un usuario con ese email' });

        PassHelper.encriptaPassword(pass).then(hash => {
            const ahora = moment().unix();
            const nuevoUsuario = {
                displayName: name,
                email: email,
                password: hash,
                signupDate: ahora,
                lastLogin: ahora
            };

            db.user.save(nuevoUsuario, (err, usuarioGuardado) => {
                if (err) return res.status(500).json({ result: 'KO', msg: err });
                const token = TokenHelper.creaToken(usuarioGuardado);
                res.json({ result: 'OK', token: token, usuario: usuarioGuardado });
            });
        }).catch(err => res.status(500).json({ result: 'KO', msg: err }));
    });
});

app.post('/api/auth/login', (req, res, next) => {
    const { email, pass } = req.body;

    if (!email || !pass) return res.status(400).json({ result: 'KO', msg: 'Debe suministrar un correo y una contraseña' });

    db.user.findOne({ email: email }, (err, usuario) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        if (!usuario) return res.status(401).json({ result: 'KO', msg: 'El usuario no está registrado o la contraseña no es correcta' });

        PassHelper.comparaPassword(pass, usuario.password).then(passOK => {
            if (!passOK) return res.status(401).json({ result: 'KO', msg: 'El usuario no está registrado o la contraseña no es correcta' });

            const ahora = moment().unix();
            db.user.update(
                { _id: usuario._id },
                { $set: { lastLogin: ahora } },
                { safe: true, multi: false },
                (err, result) => {
                    if (err) return res.status(500).json({ result: 'KO', msg: err });
                    usuario.lastLogin = ahora;
                    const token = TokenHelper.creaToken(usuario);
                    res.json({ result: 'OK', token: token, usuario: usuario });
                }
            );
        }).catch(err => res.status(500).json({ result: 'KO', msg: err }));
    });
});

// Lanzamos el servicio mediante HTTPS
https.createServer({
    cert: fs.readFileSync('./cert/cert.pem'),
    key: fs.readFileSync('./cert/key.pem')
}, app).listen(port, () => {
    console.log(`API AUTH ejecutándose en https://localhost:${port}/api/{user|auth}/{id}`);
});