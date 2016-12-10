<?php
require 'config.php';
require 'vendor/autoload.php';

use OTPHP\TOTP;
use Ifsnop\Mysqldump as IMysqldump;

class MyServer {
	const PUBKEY = 'server.pub';
	const PRIVKEY = 'server.key';

	function __construct() {
		$this->route( $_POST['cmd'] );
	}

	function route( $cmd ) {
		switch( $cmd ) {
			case 'auth':
				$this->cmd_auth();
				break;
			case 'pre':
				$this->cmd_pre();
				break;
			case 'dump':
				$this->cmd_dump();
				break;
			default:
				$this->get_cmd( $cmd );
		}
	}

	function auth( $otp ) {
		error_log( 'auth()' );
		$totp = new TOTP( Config::EMAIL, Config::OTPSECRET );
		if ( ! $totp->verify( $otp ) ) {
			error_log( 'OTP has not verified.' );
			$this->stop();
		}
	}

	function decrypt( $data, $envkey ) {
		$pkeyid = openssl_pkey_get_private( file_get_contents( self::PRIVKEY ), Config::PRIVKEYSECRET );
		if ( ! $pkeyid ) {
			error_log( openssl_error_string() );
		}

		if ( ! openssl_open( $data, $decrypted, $envkey, $pkeyid ) ) {
			error_log( openssl_error_string() );
		}

		return $decrypted;
	}

	function send_public_key() {
		error_log( 'send_public_key()' );
		$fp = fopen( self::PUBKEY, 'r' );
		header( 'Content-Type: text/plain' );
		header( 'Content-Length: ' . filesize( self::PUBKEY ) );
		fpassthru( $fp );
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

	function get_cmd( $enc_cmd ) {
		error_log( 'SID: ' . $_POST['sid'] );
		session_id( $_POST['sid'] );
		session_start();
		$key = $this->create_session_key( $_SESSION['premaster'] );
		error_log( 'SID KEY: ' . bin2hex($key) );
		$iv_size = mcrypt_get_iv_size( MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC );
		$this->iv = substr($enc_cmd, 0, $iv_size);
		error_log( 'IVDEC: '. bin2hex( $this->iv ) );
		$enc_cmd = substr($enc_cmd, $iv_size);
		$cmd = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $enc_cmd, MCRYPT_MODE_CBC, $this->iv);
		$cmd = trim( $cmd );
		$this->session_key = $key;
		error_log( 'CMD: ' . $cmd );
		//$this->stop();
		$this->route( $cmd );
	}

	function stop() {
		exit;
	}

	function cmd_auth() {
		error_log( 'CMD auth' );
		error_log( 'Key: ' . $_POST['key'] );
		$this->auth( $_POST['key'] );
		$this->send_public_key();
		$this->stop();
	}

	function cmd_pre() {
		$this->auth( $_POST['key'] );
		$premaster = $this->decrypt( $_POST['pre'], $_POST['env'] );
		session_start();
		$_SESSION['premaster'] = $premaster;
		echo session_id();
		$this->stop();
	}

	function cmd_dump() {
		$dumprawfile = 'dumpraw' . time() . '.sql';
		$dumpencfile = 'dumpenc' . time() . '.sql';

		try {
			$settings = array(
				'add-drop-table' => true
			);
			$dump = new IMysqldump\Mysqldump( 'mysql:host='.Config::DBHOST.';dbname='.Config::DBNAME, Config::DBUSER, Config::DBPASS, $settings );
			$dump->start( $dumprawfile );
		} catch ( \Exception $e ) {
			die( 'mysqldump-php error: ' . $e->getMessage() );
		}

		$opts = [
				'iv'   => $this->iv,
				'key'  => $this->session_key,
				'mode' => MCRYPT_MODE_CBC
			];

		$fpr = fopen( $dumprawfile, 'rb' );
		$fpw = fopen( $dumpencfile, 'wb' );
		stream_filter_append( $fpw, 'mcrypt.rijndael-128', STREAM_FILTER_WRITE, $opts );
		while( ! feof( $fpr ) ) {
			$content = stream_get_contents( $fpr, 128*10 );
			if ( false === fwrite( $fpw, $content ) ) {
				error_log( 'Error write data to file' );
			}
		}
		fclose($fpr);
		fclose($fpw);

		$fpw = fopen( $dumpencfile, 'rb' );
		header( "Content-Type: application/octet-stream" );
		header( "Content-Length: " . filesize( $dumpencfile ) );
		fpassthru( $fpw );
		fclose( $fpw );

		unlink( $dumprawfile );
		unlink( $dumpencfile );

		$this->stop();
	}
}

$server = new MyServer();
