# Bóveda Segura - Proyecto de Criptografía

Esta es una aplicación backend desarrollada en Python con FastAPI y SQLite que implementa dos mecanismos criptográficos para la protección de datos y autenticación de usuarios.

## 1. Cifrado Simétrico (Protección de Base de Datos)
**Librería utilizada:** `cryptography.fernet` (Implementación de AES en modo CBC).
**¿Por qué se usó?** Fernet es el estándar de alto nivel en Python para cifrado simétrico. Se eligió porque no solo cifra el contenido para dar confidencialidad, sino que asegura que los datos no puedan ser manipulados o leídos sin la llave, ideal para proteger el campo `nota_cifrada` en la base de datos.
**Gestión de la llave:** La llave se genera de forma segura y se almacena exclusivamente en una variable de entorno dentro de un archivo `.env` local, nunca en el código fuente.

## 2. Firma Asimétrica (Autenticación con JWT)
**Librería utilizada:** `PyJWT` respaldada por `cryptography` (Algoritmo RS256 - RSA Signature with SHA-256).
**¿Por qué se usó?** Se eligió PyJWT con RS256 porque representa un caso de uso real de la industria para autenticación (JSON Web Tokens). Utiliza un par de claves: el servidor firma el token con una **clave privada** (garantizando quién lo emitió) y se valida con una **clave pública** (garantizando su integridad).
**Gestión de las llaves:** Las llaves RSA (2048 bits) se generan y almacenan en archivos `private_key.pem` y `public_key.pem` protegidos en el servidor.