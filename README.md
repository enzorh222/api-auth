# Backend CRUD API REST

_Ejemplo de Servicio Web tipo REST, concretamente RESTFul (WS RESTFul) creado con NodeJS y Express. Este WS proporciona un API CRUD para gestionar una base de datos MongoDB. El servicio incorpora soporte CORS, autenticación mediante token, comunicación segura mediante HTTPS con certificados digitales autofirmados, y protección adicional con Helmet._

En la siguiente tabla se muestran todas las rutas (**endpoints**) del API RESTFul:

Verbo HTTP | Ruta | Autenticación | Descripción
-----------|------|---------------|------------
<span style="color:green">GET</span> | /api | No | Obtenemos todas las colecciones existentes en la DB.
<span style="color:green">GET</span> | /api/\{coleccion\} | No | Obtenemos todos los elementos de la tabla \{coleccion\}.
<span style="color:green">GET</span> | /api/\{coleccion\}/\{id\} | No | Obtenemos el elemento indicado en \{id\} de la tabla \{coleccion\}.
<span style="color:yellow">POST</span> | /api/\{coleccion\} | Sí | Creamos un nuevo elemento en la tabla \{coleccion\}.
<span style="color:blue">PUT</span> | /api/\{coleccion\}/\{id\} | Sí | Modificamos el elemento \{id\} de la tabla \{coleccion\}.
<span style="color:red">DELETE</span> | /api/\{coleccion\}/\{id\} | Sí | Eliminamos el elemento \{id\} de la tabla \{coleccion\}.

## Seguridad 🔒

### Autenticación por Token

Las rutas POST, PUT y DELETE están protegidas mediante un middleware de autenticación. Para acceder a estas rutas, se debe incluir una cabecera `token` en la solicitud HTTP con el valor correcto.

Ejemplo de cabecera:
```
token: password1234
```

### HTTPS y Certificados Digitales

El servicio se comunica a través de un canal seguro HTTPS utilizando certificados digitales autofirmados. Los certificados se encuentran en la carpeta `cert/` del proyecto.

Para generar nuevos certificados:
```sh
cd cert
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem
rm csr.pem
cd ..
```

### Helmet

Se utiliza la biblioteca Helmet para proteger la aplicación de vulnerabilidades web conocidas mediante la configuración de cabeceras HTTP de seguridad.

### CORS

Se ha incorporado soporte CORS (Cross-Origin Resource Sharing) para permitir que aplicaciones web de tipo SPA puedan acceder al servicio desde dominios diferentes.

## Comenzando 🚀

_Estas instrucciones te permitirán obtener una copia del proyecto en funcionamiento en tu máquina local para propósitos de desarrollo y pruebas._

### Pre-requisitos 📋

Se debe tener instalado **Node JS** en el equipo de desarrollo. Las siguientes líneas muestran cómo hacerlo para **Ubuntu 20.04**:

```sh
sudo apt update
sudo apt install npm
sudo npm clean -f
sudo npm i -g n
sudo n stable
```

Para la base de datos, se puede usar **MongoDB local** con Docker:

```sh
docker compose up -d
```

O bien, utilizar **MongoDB Atlas** (base de datos en la nube). En ese caso, se debe configurar la cadena de conexión en el archivo `config.js`.

### Instalación 🔧

En primer lugar, debemos clonar el proyecto desde nuestro repositorio.

```sh
git clone https://github.com/enzorh222/api-crud-2526.git
```

Una vez clonado el repositorio, debemos instalar y actualizar todas las bibliotecas de código del proyecto:

```sh
cd api-crud-2526
npm install
```

### Configuración ⚙️

El archivo `config.js` contiene la configuración del servicio:

```javascript
module.exports = {
    PORT: process.env.PORT || 3000,
    DB: process.env.MONGODB || 'mongodb://localhost:27017/SD',
    TOKEN: 'password1234'
}
```

Para usar MongoDB Atlas, sustituir el valor de `DB` por la cadena de conexión proporcionada por Atlas.

### Ejecución ▶️

Para ejecutar el servidor en modo desarrollo:

```sh
npm start
```

El servidor se iniciará en `https://localhost:3000/api/{colecciones}/{id}`

**Nota:** Al usar certificados autofirmados, Postman puede requerir desactivar la verificación SSL en Settings.

## Construido con 🛠️

* [Node.js](https://nodejs.org/) - Entorno de ejecución
* [Express](https://expressjs.com/) - Framework web
* [MongoDB](https://www.mongodb.com/) - Base de datos NoSQL (local o Atlas)
* [mongojs](https://github.com/mongo-js/mongojs) - Biblioteca de acceso a MongoDB
* [morgan](https://github.com/expressjs/morgan) - Middleware de logging HTTP
* [cors](https://github.com/expressjs/cors) - Middleware para CORS
* [helmet](https://helmetjs.github.io/) - Middleware de seguridad HTTP
* [nodemon](https://nodemon.io/) - Herramienta de desarrollo

## Autor ✒️

* **Enzo Adolfo Rubattino Huarzaya** - [enzorh222](https://github.com/enzorh222)

## Versionado 📌

* **v3.3.0** - HTTPS, Helmet y certificados digitales (Guía 5)
* **v3.2.0** - MongoDB Atlas (Guía 4)
* **v3.1.0** - CORS y autenticación por token (Guía 4)
* **v1.0.25** - Versión inicial del proyecto

## Licencia 📄

Este proyecto está bajo la Licencia ISC.