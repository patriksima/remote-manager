# Remote Manager #

slouží ke vzdálené správě serveru přes PHP - například k dumpu databáze

Zabezpečeno skrze OTP, asymetrickou a symetrickou šifrou.

## Instalace ##

Buď jako modul Gitu.

```
git submodule add https://github.com/wrongware/remote-manager.git random5-10string
git submodule update --init --recursive
```

nebo nahrejte přímo na FTP.

Na server nahrejte jen nejnutnější soubory, ostatní smažte!

Složku přejmenujte náhodně na 5-10 písmen.

## Server ##

1. přejmenujte config-sample.php na config.php a vyplňte chybějící údaje
2. vytvořte klíče skrze create-new-server-keys.php a následně tento php soubor smažte


## Client ##

1. přejmenujte config-sample.php na config.php a vyplňte chybějící údaje - musí být shodné se serverem

## Dump DB ##

Z příkazového řádku spusťte:
```
#!php

php client.php dump http://example.com/cesta-k-adresari/server.php > dump.sql
```
