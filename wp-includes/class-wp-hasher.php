<?php

class WP_Hasher {
	public function __construct() {
                // Load compatibility library to provide password_hash() and
                // password_verify() to pre-5.5.0 versions of PHP
		require_once ABSPATH . WPINC . '/compat-password.php';
	}

	// Set up PasswordHash class
	private function InitializePasswordHash() {
		require_once ABSPATH . WPINC . '/class-phpass.php';
		$this->hasher = new PasswordHash( 8, true );
	}

	// Test whether this PHP installation can use bcrypt
	public function UseBcrypt() {
		// Versions before 5.3.7 have bugs with their bcrypt implementations
		return version_compare( PHP_VERSION, '5.3.7', '>=' );
	}

	// Test for a portable hash
	public function HashIsPortable( $hash  ) {
		return substr( $hash, 0, 3 ) === '$P$';
	}

	public function HashPassword( $password ) {
		if ( $this->UseBcrypt() ) {
			return password_hash( $password, PASSWORD_BCRYPT );
		} else {
			$this->InitializePasswordHash();
			return $this->hasher->HashPassword( $password );
		}
	}

	public function CheckPassword( $password, $hash ) {
		if ( $this->UseBcrypt() && ! $this->HashIsPortable( $hash ) ) {
			return password_verify( $password, $hash );
		} else {
			$this->InitializePasswordHash();
			return $this->hasher->CheckPassword( $password, $hash );
		}
	}
}
