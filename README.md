# Esto es una Practica Sencilla de Keytool

Tiene 3 comandos basicos:

    1.-  genkey: que se usa para almacenar en el keystore la clave publica y privada de la persona. El comando es 'python3 keytool.py  --genkey --alias "nombre del alias"' y se muestra en el keystore.

    2.- certreq: es un comando usado para crear certificados usando el alias y guardandolo con un nombre. El comando es 'python3 keytool.py --certreq --alias alumno --cn "nombre de como lo quieres guardar"'.

    3.- help se usa para saber la  información y los comandos del keytool. Su comando es 'python3 keytool.py --help'.