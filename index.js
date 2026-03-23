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

// añadimos un trigger previo a las rutas
app.param("coleccion", (req, res, next, coleccion) => {
    req.collection = db.collection(coleccion);
    return next();
});

// routes
app.get('/api', AuthMiddleware.auth, (req, res, next) => {
    db.getCollectionNames((err, colecciones) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(colecciones);
    });
});

app.get('/api/:coleccion', AuthMiddleware.auth, (req, res, next) => {
    req.collection.find((err, coleccion) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(coleccion);
    });
});

app.get('/api/:coleccion/:id', AuthMiddleware.auth, (req, res, next) => {
    const elementoId = req.params.id;
    req.collection.findOne({ _id: id(elementoId) }, (err, elementoRecuperado) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(elementoRecuperado);
    });
});

app.post('/api/:coleccion', AuthMiddleware.auth, (req, res, next) => {
    const nuevoElemento = req.body;

    req.collection.save(nuevoElemento, (err, coleccionGuardada) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(coleccionGuardada);
    });
});

app.put('/api/:coleccion/:id', AuthMiddleware.auth, (req, res, next) => {
    const elementoId = req.params.id;
    const nuevosRegistros = req.body;

    req.collection.update(
        { _id: id(elementoId) },
        { $set: nuevosRegistros },
        { safe: true, multi: false },
        (err, result) => {
            if (err) return res.status(500).json({ result: 'KO', msg: err });
            res.json(result);
        });
});

app.delete('/api/:coleccion/:id', AuthMiddleware.auth, (req, res, next) => {
    const elementoId = req.params.id;

    req.collection.remove({ _id: id(elementoId) }, (err, resultado) => {
        if (err) return res.status(500).json({ result: 'KO', msg: err });
        res.json(resultado);
    });
});

// Lanzamos el servicio mediante HTTPS
https.createServer({
    cert: fs.readFileSync('./cert/cert.pem'),
    key: fs.readFileSync('./cert/key.pem')
}, app).listen(port, () => {
    console.log(`API RESTful CRUD ejecutándose en https://localhost:${port}/api/{colecciones}/{id}`);
});