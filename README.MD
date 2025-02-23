# Configuración y Ejecución del Proyecto

## **¡ATENCIÓN!**

**Este proyecto puede contener errores, problemas y aún no está terminado. Habrá más mejoras próximamente, pero la idea es que empiecen a realizar conexiones con su front.**

Este proyecto utiliza `pnpm` como el gestor de paquetes. Sigue los pasos a continuación para configurar y ejecutar el proyecto:

## Prerrequisitos

- Asegúrate de tener `pnpm` instalado. Si no, puedes instalarlo globalmente usando npm:
    ```sh
    npm install -g pnpm
    ```

## Instalación

1. Clona el repositorio en tu máquina local.
2. Navega al directorio del proyecto.
3. Instala las dependencias del proyecto usando `pnpm`:
     ```sh
     pnpm install
     ```

## Ejecutando el Proyecto en dev

Después de instalar las dependencias, puedes ejecutar el proyecto con el siguiente comando:

```sh
pnpm run dev
```

## Ejecutando el Proyecto con Docker

Para ejecutar el proyecto utilizando Docker, sigue los siguientes pasos:

1. Asegúrate de tener Docker instalado en tu máquina.
2. Construye la imagen de Docker:
    ```sh
    docker build -t api_simulacion .
    ```
3. Corre el contenedor de Docker:
    ```sh
    docker run -p 3000:3000 api_simulacion
    ```

# Posibles mitigaciones para el API

1. **Validación de Entrada**:
    - **Descripción**: Asegurarse de que todos los datos de entrada sean validados y sanitizados para prevenir inyecciones de código y otros ataques.
    - **Ejemplo**: Utilizar expresiones regulares para validar correos electrónicos y números de teléfono.

2. **Autenticación y Autorización**:
    - **Descripción**: Implementar mecanismos robustos de autenticación y autorización para asegurar que solo los usuarios autorizados puedan acceder a los recursos.
    - **Ejemplo**: Utilizar OAuth 2.0 para la autenticación y JWT (JSON Web Tokens) para la autorización.

3. **Cifrado de Datos**:
    - **Descripción**: Cifrar los datos sensibles tanto en tránsito como en reposo para protegerlos de accesos no autorizados.
    - **Ejemplo**: Utilizar HTTPS para la comunicación segura y AES (Advanced Encryption Standard) para cifrar datos almacenados.

4. **Control de Acceso Basado en Roles (RBAC)**:
    - **Descripción**: Implementar RBAC para asegurar que los usuarios solo puedan acceder a los recursos necesarios para sus roles específicos.
    - **Ejemplo**: Un administrador puede tener acceso completo, mientras que un usuario regular solo puede acceder a sus propios datos.

5. **Protección contra CSRF (Cross-Site Request Forgery)**:
    - **Descripción**: Implementar tokens CSRF para prevenir que un atacante pueda realizar acciones en nombre de un usuario autenticado.
    - **Ejemplo**: Incluir un token CSRF en cada formulario y verificarlo en el servidor antes de procesar la solicitud.

6. **Limitación de Tasa (Rate Limiting)**:
    - **Descripción**: Implementar limitación de tasa para prevenir ataques de denegación de servicio (DoS) y abuso de API.
    - **Ejemplo**: Limitar el número de solicitudes a 100 por minuto por usuario.

7. **Registro y Monitoreo**:
    - **Descripción**: Implementar registros y monitoreo continuo para detectar y responder a actividades sospechosas.
    - **Ejemplo**: Utilizar herramientas como ELK Stack (Elasticsearch, Logstash, Kibana) para centralizar y analizar logs.

8. **Protección contra XSS (Cross-Site Scripting)**:
    - **Descripción**: Sanitizar todas las entradas y salidas para prevenir la inyección de scripts maliciosos.
    - **Ejemplo**: Utilizar bibliotecas como DOMPurify para limpiar el HTML antes de renderizarlo en el navegador.

9. **Configuración Segura del Servidor**:
    - **Descripción**: Asegurarse de que el servidor esté configurado de manera segura para minimizar las vulnerabilidades.
    - **Ejemplo**: Deshabilitar métodos HTTP inseguros como TRACE y TRACK, y asegurar que las cabeceras de seguridad estén configuradas correctamente.

10. **Actualizaciones y Parches**:
     - **Descripción**: Mantener el software y las dependencias actualizadas para protegerse contra vulnerabilidades conocidas.
     - **Ejemplo**: Aplicar parches de seguridad tan pronto como estén disponibles y utilizar herramientas como Dependabot para gestionar actualizaciones de dependencias.
