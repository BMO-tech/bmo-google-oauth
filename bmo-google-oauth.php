<?php
/*
Plugin Name: BMO's GoogleOAuth
Description:  Allows autologin against Google Apps OAuth service -- BMO Fixed
Version: 1.3
Author: Servian Pty Ltd, BMO
License: GPLv2 Copyright (c) 2013 Servian Pty Ltd
*/

class GoogleOAuth {

	/**
	 * __construct
	 *
	 */
	public function __construct() {
		add_action( 'login_form', array( &$this, 'googleoauth_login_form' ) );
		add_action( 'wp_login', array( &$this, 'googleoauth_login' ), 1, 2 );
		add_action( 'wp_logout', array( &$this, 'googleoauth_logout' ), 1, 2 );
		if ( is_admin() ) {
			//AJAX stuff
			add_action( 'wp_ajax_googleoauth-callback', array( $this, 'googleoauth_callback' ) );
			add_action( 'wp_ajax_nopriv_googleoauth-callback', array( $this, 'googleoauth_callback' ) );

			add_action( 'admin_menu', array( $this, 'google_oauth_plugin_page' ) );
			add_action( 'admin_init', array( $this, 'google_oauth_init' ) );
		}
	} //end __construct

	/**
	 * check_option - used by launchkey_page_init
	 *
	 * @param $input
	 *
	 * @return array
	 */
	public function check_option( $input ) {
		if ( isset( $input['client_id'] ) ) {
			$client_id = trim( $input['client_id'] );
			if ( get_option( 'google_oauth_client_id' ) === FALSE ) {
				add_option( 'google_oauth_client_id', $client_id );
			}
			else {
				update_option( 'google_oauth_client_id', $client_id );
			}
		}
		else {
			$client_id = '';
		}

		if ( isset( $input['client_secret'] ) ) {
			$client_secret = trim( $input['client_secret'] );
			if ( get_option( 'google_oauth_client_secret' ) === FALSE ) {
				add_option( 'google_oauth_client_secret', $client_secret );
			}
			else {
				update_option( 'google_oauth_client_secret', $client_secret );
			}
		}
		else {
			$client_secret = '';
		}

		if ( isset( $input['allowed_domains'] ) ) {
			$allowed_domains = trim( $input['allowed_domains'] );
			if ( get_option( 'google_oauth_allowed_domains' ) === FALSE ) {
				add_option( 'google_oauth_allowed_domains', $allowed_domains );
			}
			else {
				update_option( 'google_oauth_allowed_domains', $allowed_domains );
			}
		}
		else {
			$allowed_domains = '';
		}

		if ( true ) {
			$autologin_active = isset( $input['autologin_active']);

			if ( get_option( 'google_oauth_autologin_active' ) === FALSE ) {
				add_option( 'google_oauth_autologin_active', $autologin_active );
			}
			else {
				update_option( 'google_oauth_autologin_active', $autologin_active );
			}
		}

		$options = array( $client_id, $client_secret, $allowed_domains, $autologin_active );
		return $options;
	} //end check_option

	/**
	 * create_admin_page - used by launchkey_plugin_page
	 */
	public function create_admin_page() {
		echo '<div class="wrap">';
		screen_icon();
		echo '    <h2>Google OAuth</h2>';
		echo '    <form method="post" action="options.php">';
		settings_fields( 'google_oauth_option_group' );
		do_settings_sections( 'google-oauth-setting-admin' );
		submit_button();
		echo '    </form>';
		echo '</div>';
	} //end create_admin_page

	/**
	 * create_app_key_field
	 */
	public function create_client_id_field() {
		echo '<input type="text" id="client_id" name="array_key[client_id]" value="' . get_option( 'google_oauth_client_id' ) . '">';
	}

	/**
	 * create_client_secret_field
	 */
	public function create_client_secret_field() {
		echo '<input type="text" id="client_secret" name="array_key[client_secret]" value="' . get_option( 'google_oauth_client_secret' ) . '">';
	}

	/**
	 * create_allowed_domains
	 */
	public function create_allowed_domains() {
		echo '<input type="text" id="allowed_domains" name="array_key[allowed_domains]" value="' . get_option( 'google_oauth_allowed_domains' ) . '">';
	}

	/**
	 * create_allowed_domains
	 */
	public function create_autologin_active_field() {
		echo '<input type="checkbox" id="autologin_active" name="array_key[autologin_active]" value="1" ' . (get_option( 'google_oauth_autologin_active' ) == '1' ? 'checked="checked"' : '' ) . '>';
	}

	/**
	 * create_allowed_domains
	 */
	public function create_redirect_url_field() {
		echo '<input type="text" id="redirect_url" name="array_key[redirect_url]" readonly="true" value="' . admin_url() .  'admin-ajax.php?action=googleoauth-callback">';
	}

	/**
	 * page init function - called from admin_init
	 *
	 * this function is called before anything else is done on the admin page.
	 *
	 * 1. Checks if OAuth ID token has expired
	 * 2. Uses refresh token from session to revalidate ID token
	 * 3. On failure, logs user out of Wordpress
	 */
	public function googleoauth_page_init() {
		$is_google_oauth_user = get_user_meta( wp_get_current_user()->ID, 'google-oauth-user', true);

		if ( is_user_logged_in() && $is_google_oauth_user != '' && ! isset( $_COOKIE['google_oauth_id_token'] ) ) {
			wp_logout();
			wp_redirect( wp_login_url());
			exit;
		}
	}

	/**
	 * handles the callback and authenticates against google oauth API.
	 *
	 * performed by wp_ajax*_callback action
	 *
	 */
	public function googleoauth_callback() {
		if ( isset( $_GET['error'] ) ) {
			wp_redirect( wp_login_url() . "?googleoauth-error=1" );
		}

		$code = $_GET['code'];

		$client_id =  get_option( 'google_oauth_client_id' );
		$client_secret =  get_option( 'google_oauth_client_secret' );
		$redirect_url = admin_url() . 'admin-ajax.php?action=googleoauth-callback';

		if ( isset( $code ) ) {
			if ( true ) {
				//make oauth call
				$oauth_result = wp_remote_post( "https://accounts.google.com/o/oauth2/token", array(
						'body' => array(
							'code' => $code,
							'client_id' => $client_id,
							'client_secret' => $client_secret,
							'redirect_uri' => $redirect_url,
							'grant_type' => 'authorization_code'
						)
				));

				if ( ! is_wp_error( $oauth_result ) ) {
					$oauth_response = json_decode( $oauth_result['body'], true );
				}
				else {
					wp_redirect( wp_login_url() . "?googleoauth-error=1" );
				}

				if ( isset( $oauth_response['access_token'] ) ) {
					//vars
					$oauth_token_type        = $oauth_response['token_type'];
					$oauth_id_token          = $oauth_response['id_token'];
					$oauth_access_token      = $oauth_response['access_token'];
					$oauth_expiry            = $oauth_response['expires_in'] + current_time( 'timestamp', true );
					$idtoken_validation_result = wp_remote_get('https://www.googleapis.com/oauth2/v1/tokeninfo?id_token=' . $oauth_id_token);

					if( ! is_wp_error($idtoken_validation_result)) {
						$idtoken_response = json_decode($idtoken_validation_result['body'], true);
						setcookie( 'google_oauth_id_token', $oauth_id_token, $oauth_expiry, COOKIEPATH, COOKIE_DOMAIN );
						setcookie( 'google_oauth_username', $oauth_username,  (time() + ( 86400 * 7)), COOKIEPATH, COOKIE_DOMAIN );
					} else {
						wp_redirect( wp_login_url() . "?googleoauth-token-error=1" );
					}
					$oauth_username = $idtoken_response['email'];
					$user = get_user_by('login', $oauth_username);
					$new_user_id = '';

					if (! isset( $user->ID ) ) {
						$new_user_id = $this->try_create_domain_user($oauth_username);
						$user = (is_numeric($new_user_id)) ? get_user_by('id', $new_user_id) : $new_user_id;
					}

					// this is NOT an else condition related to the previous IF
					if(isset($user->ID)) {
						$is_google_oauth_meta_exists = (get_user_meta($user->ID, 'google-oauth-user', true) != '');
						if ( ! $is_google_oauth_meta_exists ) {
							add_user_meta( $user->ID, 'google-oauth-user', true, true);
						}

						wp_set_auth_cookie( $user->ID, false );
                        if(isset($_COOKIE['requested_url'])){
                            wp_redirect($_COOKIE['requested_url']);
                        }else{
						  wp_redirect( home_url() );
                        }
					} else {
						wp_redirect( wp_login_url() . "?google-domain-error=1&google-oauth-username=" . urlencode($oauth_username) . '&error='.urlencode($user) );
					}

				}
				else {
					wp_redirect( wp_login_url() . "?google-oauth-error=1" );
				}
			}
			else {
				wp_redirect( wp_login_url() . "?google-oauth-error=1" );
			}
		}
		else {
			wp_redirect( wp_login_url() . "?google-oauth-error=1" );
		}
	}

	/**
	 *
	 */
	private function try_create_domain_user($username) {
		if ($this->is_domain_allowed($username)) {
			$user = get_userdatabylogin($username);
			$random_password = wp_generate_password( 12, false );
			$user_id = wp_create_user( $username, $random_password, $username);
			add_user_meta( $user_id, 'google-oauth-user', true, true);
			if(! is_wp_error($user_id) ) {
				return $user_id;
			} else {
				return $user_id->get_error_message();
			}
		} else {
			return null;
		}
	}

	/**
	 * checks if user's domain is allowed for wordpress @author servian
	 * i.e. someone@googleapps-enabled-business.com is ok, whilst someone@gmail.com is not allowed
	 *
	 * @param unknown $username
	 * @return boolean
	 */
	private function is_domain_allowed($username) {
		$parts = explode("@",$username);
		if (count($parts) != 2) {
			return false;
		} else {
			$user_domain = $parts[1];

			$domains_allowed_field = get_option('google_oauth_allowed_domains');

			if (isset($domains_allowed_field) && trim($domains_allowed_field) != '') {
				$domains_allowed = explode(",",ereg_replace(' ','',$domains_allowed_field));
			}
			if (is_array($domains_allowed)) {
				foreach ($domains_allowed as $domain) {
					if (strtolower($user_domain) == strtolower($domain)) {
						return true;
					}
				}
			}
			return false;
		}
	}


	/**
	 * wp-login.php with google specifics
	 *
	 * @access public
	 * @return void
	 */
	public function googleoauth_login_form() {
		$clientId =  get_option( 'google_oauth_client_id' );
		$autologinActive =  get_option( 'google_oauth_autologin_active' );

		$redirectUrl = admin_url( 'admin-ajax.php?action=googleoauth-callback' );
		setcookie('requested_url', $_REQUEST["redirect_to"] );


		if ( isset( $_GET['google-oauth-error'] ) ) {
			echo '<div style="padding:10px;background-color:#FFDFDD;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><p style="line-height:1.6em;"><strong>Error!</strong> Error connecting to Google Apps. </p></div><br>';
		}
		else if ( isset( $_GET['google-domain-error'] ) ) {
			$username = $_GET['google-oauth-username'];
			echo '<div style="padding:10px;background-color:#FFDFDD;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><p style="line-height:1.6em;"><strong>Error!</strong> User ' . $username . ' is not authorised to login. </p></div><br>';
		}
		else if ( $autologinActive && !isset( $_GET['loggedout']) ){
			//straight through to autologin - no form rendered
			$loginUrl = 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=' . $clientId . '&redirect_uri=' . $redirectUrl . '&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&login_hint=@servian.com.au&access_type=offline';
			wp_redirect($loginUrl);
			exit;
		}
	}

	/**
	 * logout method - called from wp_logout action
	 *
	 * @access public
	 * @return void
	 */
	public function launchkey_logout() {
		setcookie( 'google_oauth_id_token', '1', 0, COOKIEPATH, COOKIE_DOMAIN );
		setcookie( 'google_oauth_username', '1',  0, COOKIEPATH, COOKIE_DOMAIN );
	}

	/**
	 * google_oauth_init
	 *
	 * Invoked by admin_init action
	 *
	 */
	public function google_oauth_init() {
		$this->googleoauth_page_init();

		register_setting( 'google_oauth_option_group', 'array_key', array( $this, 'check_option' ) );

		add_settings_section( 'setting_section_id', 'Google API Settings', array(
				$this,
				'google_oauth_section_info'
			), 'google-oauth-setting-admin');

		add_settings_field( 'autologin_active', 'Activate auto-login',	array(
				$this,
				'create_autologin_active_field'
			),
			'google-oauth-setting-admin', 'setting_section_id');


		add_settings_field( 'client_id', 'Client ID',	array(
				$this,
				'create_client_id_field'
			),
			'google-oauth-setting-admin', 'setting_section_id');

		add_settings_field( 'client_secret', 'Secret Key', array(
				$this,
				'create_client_secret_field'
			),
			'google-oauth-setting-admin', 'setting_section_id');

		add_settings_field( 'redirect_url', 'Redirect URL', array(
				$this,
				'create_redirect_url_field'
			),
			'google-oauth-setting-admin', 'setting_section_id');

		add_settings_section( 'app_setting_section_id', 'Authentication Settings', array(
				$this,
				'google_oauth_app_settings_section_info'
			), 'google-oauth-setting-admin');

		add_settings_field( 'allowed_domains', 'Allowed domain', array(
				$this,
				'create_allowed_domains'
			),
			'google-oauth-setting-admin', 'app_setting_section_id');
	}

	/**
	 * google_oauth_plugin_page
	 *
	 * this function is invoked by admin_menu action
	 */
	public function google_oauth_plugin_page() {
		// Plugin Settings page and menu item
		add_options_page( 'Google OAuth', 'Google OAuth', 'manage_options', 'google-oauth-setting-admin',
		array( $this, 'create_admin_page' ) );
	}

	/**
	 *
	 */
	public function google_oauth_section_info() {
		echo '<p>Please use the <a href="https://cloud.google.com/console">Google Cloud Console</a> to setup OAuth 2.0 Google Apps authentication.</p>' .
				'<p>Redirect URL field is automatically generated and is read-only. You must register it with Google OAuth to enable authentication.';
	}

	/**
	 *
	 */
	public function google_oauth_app_settings_section_info() {
		echo 'Limit domain names to allow authentication. Add Multiple Domains using a comma. (IE: abc.com, 123.org, efg.net)';
	}

}

$GoogleOAuth = new GoogleOAuth();

?>
