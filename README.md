Autenticación con Node.js, Express y JWT

Este proyecto implementa un sistema completo de autenticación y autorización utilizando Node.js, Express y JSON Web Tokens (JWT).
Su objetivo es ofrecer una base sólida y segura para manejar el registro e inicio de sesión de usuarios, la protección de rutas y la validación de tokens.

El sistema puede funcionar con una base de datos MySQL (para entornos de producción) o sin base de datos (para pruebas o desarrollo local, usando un arreglo en memoria o archivo JSON).

Descripción general

La autenticación basada en JWT (JSON Web Token) es una de las formas más modernas y seguras de controlar el acceso en aplicaciones web y móviles.
En lugar de mantener sesiones en el servidor, se generan tokens firmados que contienen la identidad del usuario y un tiempo de expiración.
Estos tokens se envían en cada petición protegida mediante el encabezado HTTP Authorization: Bearer <token>.

Este proyecto incluye las siguientes características:

Registro de nuevos usuarios con hash seguro de contraseñas mediante bcrypt.

Inicio de sesión con validación de credenciales.

Generación de Access Token (corto plazo) y Refresh Token (largo plazo).

Renovación de tokens expirados sin necesidad de volver a iniciar sesión.

Middleware para proteger rutas privadas.

Conexión a MySQL (opcional) o almacenamiento en memoria.

Configuración mediante variables de entorno con .env.

Ejemplo de uso de curl para probar los endpoints desde consola.

Tecnologías utilizadas
Tecnología	Descripción
Node.js	Entorno de ejecución para JavaScript del lado del servidor.
Express.js	Framework minimalista para construir APIs REST.
JWT (jsonwebtoken)	Para generar y verificar tokens de autenticación.
bcryptjs	Encriptación de contraseñas.
dotenv	Manejo de variables de entorno.
MySQL2 (opcional)	Base de datos relacional para almacenamiento de usuarios.
Requisitos previos

Tener instalado Node.js
 v16 o superior.

Tener instalado MySQL
 (opcional).

Editor recomendado: Visual Studio Code.
