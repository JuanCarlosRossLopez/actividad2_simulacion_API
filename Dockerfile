# Usa una imagen base de Node.js 18
FROM node:14-slim

# Establece el directorio de trabajo
WORKDIR /app

# Copia archivos de dependencias
COPY package.json pnpm-lock.yaml ./

# Instala pnpm y dependencias
RUN npm install

# Copia el resto de los archivos
COPY . .

# Cambia al usuario no-root (buena práctica)
USER node

# Expone el puerto y ejecuta
EXPOSE 3000
CMD ["npm", "run", "dev"]
