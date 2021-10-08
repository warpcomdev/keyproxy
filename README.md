# Keyproxy

Proxy inverso HTTP para servicios desplegados en kubernetes que utilicen pods individuales por cliente.

Originalmente desarrollado para WSO2.

## Mapa de directorios

- configs: Contiene el fichero [pod.yaml](configs/pod.yaml) que describe el pod que se creará cuando inicie sesión un cliente.
- internal: Módulos de **go** para el backend.
- podstatic: Recursos estáticos servidos por un `http.FileServer` de **go** en la ruta `/podstatic`. Se genera a partir de los directorios `static` y `src` con el comando `npm run build`.
- src: Código fuente del frontend, usando **sveltekit**.
- static: Recursos estáticos del frontend.
- templates: Plantillas go para la interfaz alternativa en modo full server-side (se activa si no existe un `index.html` en el directorio `podstatic`).
