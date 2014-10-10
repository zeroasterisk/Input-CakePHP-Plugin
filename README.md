# Input CakePHP Plugin

Input access helper, and sanitization.

## Install

    cd app
    git clone https://github.com/zeroasterisk/Input-CakePHP-Plugin.git Plugin/Input
    echo "CakePlugin::load('Input', array('bootstrap' => false, 'routes' => false));" >> Config/bootstrap.php

## Configure: Global

Configuration is "setable" in app/Config/Input.php

A default version is ready for you, and you can put it in place with:

    cp app/Plugin/Input/Config/Input.default.php app/Config/Input.php

If you don't have `Configure::read('Input')` defined, we will use our own,
internal default Configuration.

    fields:
      *.email = 'email'   FILTER_SANITIZE_EMAIL   & strip_tags
      *.url   = 'url'     FILTER_SANITIZE_URL     & strip_tags
      *       = 'string'  FILTER_SANITIZE_STRING  & strip_tags

See Configuration Input sanitizationKeyMap to see all options

## Configure: On the Component

You can set configuration per controller when you initialize the Component

    $components = array(
      'Input.Input' => array(
        'settings' => array(
          'fields' => array(
            'Post.body' => 'anything',
          ),
          'sanitizationKeyMap' => array(
            'anything' => array(
              'filter' => false,
              'xss' => true,
            )
            'custom' => array(
              'strip_tags' => true,
              'filter' => FILTER_SANITIZE_STRING,
              'filterOptions' => FILTER_FLAG_ENCODE_LOW | FILTER_FLAG_ENCODE_HIGH | FILTER_FLAG_ENCODE_AMP
              'preg_replace' => ['/(bad|word|list|here)/gi'],
              'xss' => false,
            ),
          )
        )
      )
    );

## Configuration

### Input.fields

The list works "top down"
First matching key, wins (only it's rule will be applied)
If no Input.Fields match, nothing is done

**Keys:** Flattened data key matching whole strings, or patterns as matched by
[fnmatch()](http://php.net/manual/en/function.fnmatch.php)
or patterns as matched by
[preg\_match()](http://php.net/manual/en/function.preg_match.php)

Example Keys:

* `User.email`
* `*.body`
* `Post.*`
* `#User\.email#`
* `/Comment.*\.subject$/`
* `/.*\.body$/`

**Values:** A "config key" to tell us what type of sanitization to run.

see Input.sanitizationKeyMap

**default Input.fields:**

			'fields' => [
				'/.*\.email$/' => 'email',
				'/.*\.url$/'   => 'url',
				'*' => 'string'
			],

### Input.sanitizationKeyMap

**Sanitization Keys**

    email:    FILTER_SANITIZE_EMAIL   & strip_tags
    url:      FILTER_SANITIZE_URL     & strip_tags
    string:   FILTER_SANITIZE_STRING  & strip_tags
    html:     FILTER_UNSAFE_RAW * FILTER_FLAG_NO_ENCODE_QUOTES | FILTER_FLAG_STRIP_HIGH
              (html allowed, xss checking done)
    blacklist: Simple preg_replace done to strip blacklisted terms
              (html allowed, xss checking done)
              ['/(bad|word|list|here)/i', '/^lorem.*$/i']
    anything: (no filter, no xss check

You can add your own sanitization keys... just make a new key and setup whatever
you config you want as the value.

**Config for Sanitization Keys**

    strip_tags = true or string $allowable_tags
      http://php.net/manual/en/function.strip-tags.php
    filter = constant or null
      FILTER_* filters for Sanitize
      http://php.net/manual/en/filter.filters.sanitize.php
    filterOptions = constant or array or null
      FILTER_* flags for Sanitize joined via bitwise opperators
      or an associative array of options for the filter_var() function
      http://php.net/manual/en/filter.filters.flags.php
    preg_replace = array or string
      if specified, we will do a preg_replace($patterns, '', $value)
    xss = bool [true]
      if true, we look to see if we can detect any known XSS attack and if so,
      we throw an UnsafeInputException

NOTE:
* if you need to allow HTML with style and javascript and the like, skip XSS
 * then specify: `['filter' => false, 'xss' => false]`
* if you need to want to allow HTML and still do XSS checking
 * then specify: `['filter' => false, 'xss' => true]`

### Input.patternsXSS

XSS Checking

* for key: `email`, `url`, `string` - all HTML is stripped, so it shouldn't matter.
* for key: `anything` - we do not check for XSS *(look out!)*
* for key: `html`, 'blacklist' - we will throw an UnsafeInputException for:
 * javascript, java, vbscript, etc. (anywhere in the text)
 * style attributes (which are often exploits)
 * etc.


## Usage: Access Input

Information can be accessed in a lot of places, in CakePHP.

Before 3, named params (passed args) were the norm, but now CakePHP is moving to query string.

Sometimes routes put things in params, sometimes in named.

Use this handy lookup tool to find a key, or return the default.

    $value = $this->Input->get($name, $default=false);

    $id = $this->Input->get('id');

This will look in the following paths and return the first *set* value:

    $this->request->params['id']
    $this->request->named['id']
    $this->request->query['id']
    $this->request->data['id']

Likewise, we can use this with a default value too (without a default, we
default to `false`):

    $type = $this->Input->get('type', 'default-type');


## Usage: Secure/Sanitize Input

* TODO

(build data sanitization, which is configurable...
we want to defeat security scanners, XSS scripts, spammers, and hackers alike)

## Usage: Secure/Sanitize Input - Custom CleanData Lib

(optional)

You may create your own `app/Lib/CleanData.php` and expose an `all()` method on
it... We pass in `$this->request->data` as the first argument.

    // app/Lib/CleanData.php
    $data = CleanData::all($data);


