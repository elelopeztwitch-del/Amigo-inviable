# Amigo Invisible Seguro

Web estática preparada para GitHub Pages + Firebase Authentication + Cloud Firestore.

## Qué incluye
- Crear salas con código de acceso.
- Unirse a una sala desde otro móvil u ordenador.
- Registro de nombre, talla y preferencias.
- Vestíbulo sincronizado en tiempo real.
- Sorteo sin autoasignaciones.
- Carta personal cifrada con ECDH P-256 + AES-GCM.
- El participante solo puede leer su propio documento de asignación.
- El administrador puede consultar quién ha abierto su carta, pero no leer las asignaciones.
- Descarga de la carta en PNG o TXT.

## 1. Crear Firebase
1. Entra en https://console.firebase.google.com/ y crea un proyecto.
2. Añade una aplicación web (icono `</>`).
3. Copia la configuración del SDK web.
4. Abre `js/firebase-config.js` y sustituye los valores `PEGA_AQUI...` y `TU-PROYECTO...`.
5. En Firebase Authentication > Sign-in method, activa **Anonymous**.
6. En Firestore Database, crea una base de datos.
7. En Firestore > Rules, pega el contenido de `firestore.rules` y pulsa Publish.

La configuración web de Firebase identifica el proyecto, pero no es una contraseña. La seguridad real depende de Authentication y de las reglas de Firestore.

## 2. Publicar en GitHub Pages
1. Crea un repositorio público en GitHub.
2. Sube TODO el contenido de esta carpeta, manteniendo las subcarpetas.
3. En el repositorio entra en Settings > Pages.
4. En Build and deployment selecciona `Deploy from a branch`.
5. Selecciona la rama `main` y la carpeta `/ (root)`.
6. Guarda. GitHub mostrará la dirección pública de la web.

## 3. Comprobarlo
- Abre la URL pública en una ventana normal.
- Crea una sala y copia el código.
- Abre la URL en otro móvil o navegador y entra con ese código.
- Registra al segundo participante.
- Para probar el sorteo hacen falta al menos dos participantes.
- Prueba las cartas desde sesiones/dispositivos diferentes.

## Importante sobre privacidad y funcionamiento
- GitHub Pages solo sirve los archivos de la web; Firestore almacena los datos compartidos.
- Las salas y los perfiles del vestíbulo son visibles para usuarios autenticados de la aplicación. No guardes información especialmente sensible.
- Los documentos de asignación solo son legibles por el UID del participante correspondiente, según las reglas incluidas.
- El administrador no debe usar la misma sesión de participante que otra persona.
- El inicio de sesión anónimo conserva la identidad en ese navegador. Si se borran los datos del navegador, se pierde esa identidad y el acceso privado a la carta guardada para ese UID.
- La expiración de 60 días se comprueba al entrar en una sala. Para borrar también automáticamente todas las subcolecciones en producción, despliega la Cloud Function incluida en `functions/` y configura facturación/plan según los requisitos de Firebase.

## 4. Limpieza automática (opcional)
La función programada se incluye como ejemplo de servidor. Para desplegarla:
1. Instala Node.js y Firebase CLI.
2. Ejecuta `firebase login`.
3. En la raíz de este proyecto ejecuta `firebase init functions` y selecciona JavaScript.
4. Copia `functions/index.js` y `functions/package.json` en la carpeta `functions` generada.
5. Ejecuta `firebase deploy --only functions`.
La programación puede requerir el plan Blaze y una cuenta de facturación de Google Cloud.

## Limitaciones conocidas
- La configuración de Firebase debe ser tuya; no hay una base de datos compartida preconfigurada.
- No se incluye un backend propio en GitHub Pages: Firestore es el servicio backend.
- Antes de usarlo con datos reales, prueba los permisos y el sorteo con un grupo pequeño.
