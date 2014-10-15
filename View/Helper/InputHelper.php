<?php
/**
 * Input Helper
 *
 */
App::uses('AppHelper', 'View/Helper');
class InputHelper extends AppHelper {
	public $helpers = array();

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
	 * @return array $args
	 */
	public function args() {
		return array_merge(
			$this->request->named,
			$this->request->passedArgs,
			$this->request->query
		);
	}

}

