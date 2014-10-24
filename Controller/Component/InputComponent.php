<?php
/**
 * Input Access and Sanitization Component
 *
 * For VERY easy access to request/input data from the Controller
 *
 * Also for simple, automated POSTed data cleanup and Sanitization
 *
 * @package Input-CakePHP-Plugin
 * @link https://github.com/zeroasterisk/Input-CakePHP-Plugin
 */
App::uses('InputClean', 'Input.Lib');
App::uses('Component', 'Controller');
class InputComponent extends Component {


	/**
	 * Default Settings
	 *
	 * Access Settings as: (array)$this->Input->settings
	 * Can Configure Globally via app/Config/Input.php
	 *
	 * @var array
	 */
	public $defaults = array(
		'auto-clean' => true,
	);


	/**
	 * Determines whether or not callbacks will be fired on this component
	 *
	 * @var bool
	 */
	public $enabled = true;

	/**
	 * Holds the reference to Controller::$request
	 *
	 * @var CakeRequest
	 */
	public $request;

	/**
	 * Holds the reference to Controller::$response
	 *
	 * @var CakeResponse
	 */
	public $response;

	/**
	 * Holds the reference to Controller::$request->params
	 *
	 * @var array
	 */
	public $params;


	/**
	 * Constructor.
	 *
	 * @param ComponentCollection $collection ComponentCollection object.
	 * @param array $settings Array of settings.
	 */
	public function __construct(ComponentCollection $collection, $settings = array()) {
		$settings = Hash::merge(
			$settings,
			['settings' => $this->defaults]
		);
		parent::__construct($collection, $settings);

		$Controller = $collection->getController();
		$this->request = &$Controller->request;
		$this->response = &$Controller->response;
	}

	/**
	 * Auto-run when component is setup
	 *
	 * (before beforeFilter)
	 *
	 * @param Controller $controller A reference to the controller
	 * @return void
	 */
	public function initialize(Controller $controller) {
		//App::uses('DebugKitDebugger', 'DebugKit.Lib');
		//DebugKitDebugger::startTimer('Input::initialize');
		if (!empty($this->settings['auto-clean'])) {
			$this->request->data = $this->cleanData($this->request->data);
			$this->request->query = $this->cleanData($this->request->query);
			//$this->request->named = $this->cleanData($this->request->named);
			//$this->request->params = $this->cleanData($this->request->params);
		}
		//DebugKitDebugger::stopTimer('Input::initialize');
	}

	/**
	 * Sanitize $this->request->data values
	 * Remove and clean all model/values which shouldn't contain HTML or otherwise dangerous values
	 *
	 * We explicity state what models can/should be cleaned
	 * We also explicity state what fields should be excluded from cleanup
	 *
	 * @param array $data
	 * @return array $data
	 */
	public function cleanData($data) {
		if (!is_array($data) || empty($data)) {
			return $data;
		}

		// clean with In's data cleanup (from this plugin)
		App::uses('InputClean', 'Input.Lib');
		$data = InputClean::all($data, $this->settings);

		// clean with a custom CleanData Lib (from the app) if it exists
		App::import('Lib', 'CleanData');
		if (!class_exists('CleanData')) {
			return $data;
		}
		$data = CleanData::all($data);

		return $data;
	}

	/**
	 * Get an input param if set, otherwise return default.
	 * Looks for the param in
	 *  request->params
	 *  request->named
	 *  request->query
	 *  request->data
	 *
	 * @param string $name
	 * @param mixed $default
	 * @return mixed $paramValue
	 */
	public function get($name, $default=false) {
		if (empty($name)) {
			return $this->args();
		}
		if (array_key_exists($name, $this->request->params)) {
			return $this->request->params[$name];
		}
		if (array_key_exists($name, $this->request->named)) {
			return $this->request->named[$name];
		}
		if (array_key_exists($name, $this->request->query)) {
			return $this->request->query[$name];
		}
		if (array_key_exists($name, $this->request->data)) {
			return $this->request->data[$name];
		}
		return $default;
	}

	/**
	 * Return a merged and cleaned array of all "normal" arguments
	 *  - named
	 *  - passedArgs
	 *  - query
	 *
	 * @param array $defaults
	 * @return array $args
	 */
	public function args($defaults = []) {
		$args = array_merge(
			(array)$defaults,
			(array)$this->request->named,
			(array)$this->request->passedArgs,
			(array)$this->request->query
		);
		unset($args['url']);
		return $args;
	}





}
