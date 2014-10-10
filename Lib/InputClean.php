<?php
/**
 * Input Sanitization Lib
 *
 * For simple, automated data cleanup and Sanitization
 *
 * Configuration is in app/Config/Input.php
 *   Need it?  do the following:
 *     cp app/Plugin/Input/Config/Input.default.php app/Config/Input.php
 *
 * Configuration may also be done via Component->settings
 *   $components = array(
 *     'Input.Input' => array(
 *       'settings' => array(
 *         'fields' => array(
 *           'Post.body' => 'anything',
*          )
*        )
*      )
*    );
 *
 * Sanitization is mostly accomplished via filter_var()
 *   http://php.net/manual/en/filter.filters.sanitize.php
 *   http://php.net/manual/en/filter.filters.flags.php
 *   (NOTE: may incorporate htmlpurify in the future)
 *
 * @package Input-CakePHP-Plugin
 * @link https://github.com/zeroasterisk/Input-CakePHP-Plugin
 */
App::uses('Hash', 'Utility');

if (!class_exists('UnsafeInputException')) {
	class UnsafeInputException extends CakeException {}
}

class InputClean {

	/**
	 * Placeholder for $settings
	 *   app/Config/InputClean.php
	 *
	 * Need it?  do the following:
	 *   cp app/Plugin/In/Config/InputClean.default.php app/Config/InputClean.php
	 *
	 * NOTE:
	 *   InputComponent settings will merge in clean(),
	 *   they will not persist on this Lib
	 *
	 * @var array
	 */
	static $settings = [];

	/**
	 * Clean an array of $data based on configured config
	 *   app/Config/InputClean.php
	 *
	 * @param array $data
	 * @param array $config one-time settings overwrite
	 * @return array $data
	 */
	static function all($data, $config = []) {
		if (empty($data) || !is_array($data)) {
			return [];
		}
		$config = self::config($config);
		$flat = Hash::flatten($data);
		foreach (array_keys($flat) as $field) {
			$flat[$field] = self::cleanField($flat[$field], $field, $config);
		}
		return Hash::expand($flat);
	}

	/**
	 * Clean a single $value, for a $field based on config known for that field
	 *
	 * @param string $value
	 * @param string $field
	 * @param array $config for all possible fields
	 * @return string $value
	 */
	static function cleanField($value, $field = null, $config = []) {
		if (is_array($value)) {
			foreach (array_keys($value) as $key) {
				$value[$key] = self::clean($value[$key], $field.$key, $config);
			}
			return $value;
		}
		if (!is_string($value)) {
			return $value;
		}

		if (array_key_exists('*', $config['fields'])) {
			// move 'default' to bottom
			$default = $config['fields']['*'];
			unset($config['fields']['*']);
			$config['fields']['*'] = $default;
		}

		foreach ($config['fields'] as $pattern => $sanitizationKey) {
			if (!self::fieldMatch($pattern, $field)) {
				continue;
			}
			return self::clean($value, $sanitizationKey);
		}

		return $value;
	}

	/**
	 * Check to see if a field matches a pattern
	 * (see Configuration Input.fields [keys])
	 *
	 * @param string $pattern
	 * @param string $field
	 * @return boolean
	 */
	static function fieldMatch($pattern, $field) {
		if (empty($pattern) || empty($field)) {
			return false;
		}
		if ($pattern == '*') {
			return true;
		}
		if (fnmatch($pattern, $field)) {
			return true;
		}
		if ($pattern[0] == substr($pattern, -1) && preg_match($pattern, $field)) {
			return true;
		}
		return false;
	}

	/**
	 * Clean a single $value, based on $sanitizationKey
	 *
	 * TODO:
	 *   implement HTML Purify
	 *
	 * @param string $value
	 * @param string $sanitizationKey (a single sanitization key, mapped to a config, with 'filter', 'xss', etc)
	 * @param array $config (optional, if empty, get from self::config())
	 * @return string $value
	 * @throws UnsafeInputException
	 */
	static function clean($value, $sanitizationKey = [], $config = []) {
		if (!is_string($value) || empty($value)) {
			return $value;
		}

		$sanitizationConfig = self::sanitizationConfig($sanitizationKey, $config);


		// strip_tags if set
		if (!empty($sanitizationConfig['strip_tags'])) {
			$value = strip_tags($value, $sanitizationConfig['strip_tags']);
		}

		// sanitization via filter_var
		if (!empty($sanitizationConfig['filter'])) {
			if (empty($sanitizationConfig['filterOptions'])) {
				$sanitizationConfig['filterOptions'] = null;
			}
			$value = self::filter($value, $sanitizationConfig['filter'], $sanitizationConfig['filterOptions']);
		}

		// remove blacklisted strings via preg_replace
		if (!empty($sanitizationConfig['preg_replace'])) {
			$value = self::blacklist($value, $sanitizationConfig['preg_replace']);
		}

		// check for XSS
		if (!empty($sanitizationConfig['xss'])) {
			if (self::detectXSS($value)) {
				throw new UnsafeInputException(
					sprintf('Unsafe Input Detected [hash: %s]',
						md5($value)
					)
				);
			}
		}

		return $value;
	}

	/**
	 * Filter strings via filter_var()
	 *
	 * @param string $value
	 * @param constant $filter
	 * @param mixed $filterOptions
	 * @return string $value
	 */
	static function filter($value, $filter, $filterOptions = null) {
		if (empty($filter)) {
			return $value;
		}
		if (!empty($filterOptions)) {
			return filter_var($value, $filter, $filterOptions);
		}
		return filter_var($value, $filter);
	}

	/**
	 * Blacklist terms via preg_replace
	 *
	 * @param string $value
	 * @param array $patterns or string $pattern (preg regular expression)
	 * @return string $value
	 */
	static function blacklist($value, $patterns) {
		if (empty($patterns)) {
			return $value;
		}
		if (!is_array($patterns)) {
			$patterns = [ $patterns ];
		}
		foreach ($patterns as $pattern) {
			$value = preg_replace($pattern, '', $value);
		}
		return $value;
	}

	/**
	 * Load the global config and merge in any manually entered config too
	 *
	 * @param array $config
	 * @return array $config
	 */
	static function config($config = []) {
		return array_merge(
			self::configGlobal(),
			$config
		);
	}

	/**
	 * Load the global config (from a file)
	 *
	 * @param array $config optionally set into the global config
	 * @return array $config
	 */
	static function configGlobal($config = []) {
		if (!empty($config)) {
			// persist anything passed into this function
			self::$settings = array_merge(
				self::configGlobal(),
				$config
			);
		}
		if (!empty(self::$settings)) {
			// already setup global
			return self::$settings;
		}
		if (file_exists(APP . 'Config' . DS . 'Input.php')) {
			try {
				Configure::load('Input');
			} catch (ConfigureException $e) {}
		}
		$global = Configure::read('Input');
		if (!is_array($global)) {
			$global = self::configDefault();
		}

		// persist for future calls
		self::$settings = $global;
		return self::$settings;
	}

	/**
	 * Default config array, if we don't have any config
	 *
	 * You can override this with Configure::write('Input');
	 *
	 * Configuration for Input/Lib/Input.php
	 *
	 * Need it?  do the following:
	 *   cp app/Plugin/Input/Config/Input.default.php app/Config/Input.php
	 *
	 * @return array $config
	 */
	static function configDefault() {
		return [
			'fields' => [
				'/.*\.email$/' => 'email',
				'/.*\.url$/'   => 'url',
				'*'            => 'string'
			],
			// XSS Matching Patterns for common exploits
			//   (NOTE: some of these might be too strict if you want to allow all HTML)
			//   bypass by using the anything sanitizationKey
			'patternsXSS' => [
				// Match any attribute starting with "on" or xmlns
				'#(<[^>]+[\x00-\x20\"\'\/])(on|xmlns)[^>]*>?#iUu',

				// Match javascript:, livescript:, vbscript: and mocha: protocols
				'!((java|live|vb)script|mocha|feed|data):(\w)*!iUu',
				'#-moz-binding[\x00-\x20]*:#u',

				// Match style attributes
				'#(<[^>]+[\x00-\x20\"\'\/])style=[^>]*>?#iUu',

				// Match unneeded tags
				'#</*(applet|meta|xml|blink|link|style|script|embed|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base)[^>]*>?#i'
			],
			// a map for sanitizationKey => sanitizationConfig
			'sanitizationKeyMap' => [
				'email' => [
					'strip_tags' => true,
					'filter' => FILTER_SANITIZE_EMAIL,
					'xss' => true,
				],
				'url' => [
					'strip_tags' => true,
					'filter' => FILTER_SANITIZE_URL,
					'filterOptions' => FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_HIGH,
					'xss' => true,
				],
				'string' => [
					'strip_tags' => true,
					'filter' => FILTER_SANITIZE_STRING,
					'filterOptions' => FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_ENCODE_HIGH,
					'xss' => true,
				],
				'html' => [
					'strip_tags' => false,
					'filter' => FILTER_UNSAFE_RAW,
					'filterOptions' => FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_HIGH,
					'xss' => true,
				],
				'blacklist' => [
					'strip_tags' => false,
					'filter' => false,
					'preg_replace' => [
						// see patternsXSS
						'#(<[^>]+[\x00-\x20\"\'\/])(on|xmlns)[^>]*>?#iUu',
						'!((java|live|vb)script|mocha|feed|data):(\w)*!iUu',
						'#-moz-binding[\x00-\x20]*:#u',
						'#(<[^>]+[\x00-\x20\"\'\/])style=[^>]*>?#iUu',
						'#</*(applet|meta|xml|blink|link|style|script|embed|object|iframe|frame|frameset|ilayer|layer|bgsound|title|base)[^>]*>?#i'
					],
					'xss' => true,
				],
				'anything' => [
					'strip_tags' => false,
					'filter' => false,
					'xss' => false,
				],
				'skip' => [],
			],
		];
	}


	/**
	 * Translate a sanitizationKey to a sanitizationConfig
	 *
	 * @param string $sanitizationKey (a single sanitization key, mapped to a config, with 'filter', 'xss', etc)
	 * @param array $config (optional, if empty, get from self::config())
	 * @return array $sanitizationConfig or empty array
	 */
	static function sanitizationConfig($sanitizationKey, $config = null) {
		if (is_array($sanitizationKey)) {
			// passed in an array, assume it is already a sanitizationConfig
			return $sanitizationKey;
		}
		if (empty($config)) {
			$config = self::config();
		}
		if (!empty($config['sanitizationKeyMap'])) {
			$config = $config['sanitizationKeyMap'];
		}
		if (!empty($config[$sanitizationKey])) {
			return $config[$sanitizationKey];
		}
		return [];
	}

	/**
	 * Given a string, this function will determine if it potentially an
	 * XSS attack and return boolean.
	 *
	 * @param string $string
	 *  The string to run XSS detection logic on
	 * @return boolean
	 *  True if the given `$string` contains XSS, false otherwise.
	 */
	static function detectXSS($string) {
		// Skip any empty or non string values
		if (empty($string) || !is_string($string)) {
			return false;
		}

		// Set the patterns we'll test against
		$config = self::config();
		$patterns = $config['patternsXSS'];
		if (empty($patterns)) {
			// skipped, no patterns exist
			return false;
		}

		if (!is_array($patterns)) {
			$patterns = [$patterns];
		}

		// Keep a copy of the original string before cleaning up
		$orig = $string;

		// URL decode
		$string = urldecode($string);

		// Convert Hexadecimals
		$string = preg_replace('!(&#|\\\)[xX]([0-9a-fA-F]+);?!e','chr(hexdec("$2"))', $string);

		// Clean up entities
		$string = preg_replace('!(&#0+[0-9]+)!','$1;',$string);

		// Decode entities
		$string = html_entity_decode($string, ENT_NOQUOTES, 'UTF-8');

		// Strip whitespace characters
		$string = preg_replace('!\s!','',$string);

		// test against all patterns, any match returns true
		foreach ($patterns as $pattern) {
			// Test both the original string and clean string
			if (preg_match($pattern, $string) || preg_match($pattern, $orig)) {
				return true;
			}
		}

		return false;
	}

}
