<?php
require 'config.php';

$res = openssl_pkey_new();

openssl_pkey_export( $res, $privkey, Config::PRIVKEYSECRET );

$pubkey = openssl_pkey_get_details( $res );
$pubkey = $pubkey['key'];

file_put_contents( 'server.key', $privkey );
file_put_contents( 'server.pub', $pubkey );

chmod( 'server.key', 0600 );
chmod( 'server.pub', 0600 );
