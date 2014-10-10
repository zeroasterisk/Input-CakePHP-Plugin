<?php
/**
 * Input Config
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
$config = [
	'Input' => [
		// map of all fields we will match against
		//   key
		//     may be a simple string:  Model.field
		//     may be a regex:          /Model\.f.+d/i
		//     may be a fnmatch string: Model.fiel*
		//   value
		//     should be a sanitizationKey (see sanitizationKeyMap)
		'fields' => [
			'/.*\.email$/' => 'email',
			'/.*\.url$/'   => 'url',
			// default "catch all" (may be omitted)
			'*'            => 'string'
		],

		/*
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
		 */

	]
];
