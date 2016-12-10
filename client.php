<?php
require 'config.php';
require 'vendor/autoload.php';

use OTPHP\TOTP;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;

class MyClient {
	private $server;
	private $server_pubkey;
	private $premaster;
	private $session_id;

	function __construct( $argv, $argc ) {
		if ( php_sapi_name() !== 'cli' ) {
			die( "Only CLI mode is allowed.\n" );
		}

		if ( $argc < 3 ) {
			die( "Help: php client.php command url-of-server\n" );
		}

		$this->server = new Client([
				'base_uri' => $argv[2]
			]);

		switch( $argv[1] ) {
			case 'dump':
				$this->cmd_dump();
				break;
		}
	}

	function create_premaster_key() {
		return openssl_random_pseudo_bytes( 16, $cstrong );
	}

	function create_session_key( $premaster ) {
		$options = [
		    'cost' => 11,
		    'salt' => Config::PREMASTER,
		];
		$key = password_hash( bin2hex( $premaster ), PASSWORD_BCRYPT, $options );
		$key = md5( $key );
		$key = hex2bin( $key );
		return $key;
	}

	function get_otp() {
		$totp = new TOTP( Config::EMAIL, Config::OTPSECRET );
		return $totp->now();
	}

	function get_server_pubkey() {
		try {
			$response = $this->server->post( 'server.php', [
					'form_params' => [
						'cmd' => 'auth',
						'key' => $this->get_otp(),
						]
				]);
		} catch ( ClientException $e ) {
			echo Psr7\str($e->getRequest());
			echo Psr7\str($e->getResponse());
			exit;
		}

		$this->server_pubkey = (string) $response->getBody();

		return $this->server_pubkey;
	}

	function send_premaster_key() {
		$this->premaster = $this->create_premaster_key();

		openssl_seal( $this->premaster, $premaster_enc, $env_keys, array( $this->server_pubkey ) );

		$response = $this->server->post( 'server.php', [
			'form_params' => [
				'cmd' => 'pre',
				'key' => $this->get_otp(),
				'env' => $env_keys[0],
				'pre' => $premaster_enc
				]
		]);

		$this->session_id = (string) $response->getBody();
	}


	function cmd_dump() {
		// faze 1 public klic serveru
		$this->get_server_pubkey();

		// faze 2 posli serveru premaster klic, dostaneme session_id
		$this->send_premaster_key();

		// faze 3 posli encryptovany prikaz asymetrickou sifrou
		$session_key = $this->create_session_key( $this->premaster );

		$iv_size = mcrypt_get_iv_size( MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC );
		$iv = mcrypt_create_iv( $iv_size, MCRYPT_RAND );

		$ciphertext = mcrypt_encrypt( MCRYPT_RIJNDAEL_128, $session_key, 'dump', MCRYPT_MODE_CBC, $iv);

		$response = $this->server->post( 'server.php', [
			'form_params' => [
				'cmd' => $iv . $ciphertext,
				'sid' => $this->session_id
				]
		]);

		$opts = [
				'iv'   => $iv,
				'key'  => $session_key,
				'mode' => MCRYPT_MODE_CBC
			];

		file_put_contents( 'client-dump-enc.sql', $response->getBody() );

		$fpr = fopen( 'client-dump-enc.sql', 'rb' );
		$fpw = fopen( 'php://output', 'wb' );
		stream_filter_append( $fpr, 'mdecrypt.rijndael-128', STREAM_FILTER_READ, $opts );
		while( ! feof( $fpr ) ) {
			$content = stream_get_contents( $fpr, 128*10 );
			if ( false === fwrite( $fpw, rtrim( $content ) ) ) {
				error_log( 'Error write data to file' );
			}
		}
		fclose($fpr);
		fclose($fpw);

		unlink( 'client-dump-enc.sql' );
	}
}

$client = new MyClient( $argv, $argc );
