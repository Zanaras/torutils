<?php

namespace TorUtils;

use DateTime;

class TorUtils {

	public $curlOptions = [
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_CONNECTTIMEOUT => 10,
	];

	public $window = 21600;
	public $enableOnionoo = true;
	public $enableTorExits = true;
	public $enableSecOpsList = false;
	public $onionooFields = 'relays,flags,or_addresses,last_seen';
	public $opts = [];

	public function __construct($userAgent) {
		$this->options[CURLOPT_USERAGENT] = $userAgent;
	}

	public function fetchExits($extra = false) {
		$all = [];
		if ($this->enableOnionoo) {
			$all = $this->parseOnionooExitsList($all, $extra);
			if (!$all) {
				# This just resets the cache array in case parseOniooExitsList returns false from failure condition.
				$all = [];
			}
		}
		if ($this->enableTorExits) {
			$all = $this->parseTorExitList($all, $extra);
		}
		#if ($this->enableSecOpsList) {
		#	$secOps = $this->parseSecOpsList($all);
		#	if ($secOps) {
		#		$all = $this->formatList($all, $secOps, $extra);
		#	}
		#}
		return $all;
	}

	public function formatList($all, $adding, $withTime) {
		if ($withTime) {
			$now = new DateTime('now');
			foreach ($adding as $each) {
				$all[] = ['ip'=>$each,'ts'=>$now];
			}
		} else {
			foreach ($adding as $each) {
				$all[] = ['ip'=>$each];
			}
		}
		return $all;
	}

	public function parseOnionooExitsList($cache = [], $extra = false) {
		$relays = $this->fetchOnionooRelays();
		if (!$relays) {
			return false;
		}
		$now = time();
		$date = new DateTime('now');
		$i = 0;
		foreach ($relays as $relay) {
			$result = [];
			$flag = false;
			if (strtotime($relay['last_seen']) < $now - $this->window) {
				# Relay was last seen before our search window. Skip.
				continue;
			}
			if (in_array("Exit", $relay['flags'])) {
				foreach ($relay['or_addresses'] as $ip) {
					$i++;
					if(count(explode(':', $ip)) > 2 && strpos($ip, '[') !== false) {
						// ipv6
						$ip = parse_url('http://'.$ip, PHP_URL_HOST);
						$ip = rtrim(ltrim($ip, '['), ']');
						$result['ip'] = $ip;
						$flag = true;
					} elseif(count(explode(':', $ip)) === 2) {
						// ipv4
						$result['ip'] = strstr( $ip, ':', true );
						$flag = true;
					}
					if ($extra) {
						// any extra data.
						$result['last_seen'] = $relay['last_seen'];
						$result['ts'] = $date;
					}
				}
			}
			if ($flag) {
				$cache[] = $result;
			}
		}
		return $cache;
	}

	public function fetchOnionooRelays() {
		$curl = curl_init("https://onionoo.torproject.org/details?fields=".$this->onionooFields);
		curl_setopt_array($curl, $this->curlOptions);
		$response_raw = curl_exec($curl);
		if ($response_raw) {
			$response = json_decode($response_raw, true);
			return $response['relays'];
		} else {
			return false;
		}
	}

	public function parseTorExitList($cache = [], $extra = false) {
		$file = file_get_contents("https://check.torproject.org/exit-addresses");
		if ($file) {
			$skip = 0;
			$now = new DateTime('now');
			$lines = preg_split('/\r\n|\r|\n/', $file);
			foreach ($lines as $line) {
				$result = [];
				$flag = false;
				if ($skip > 0) {
					$skip--;
					continue;
				}
				if (substr($line, 0, 10) === 'LastStatus') {
					$date = explode(" ", $line);
					$fullDate = $date[1].' '.$date[2];
					$when = new DateTime($fullDate);
					$limit = new DateTime("-".$this->window." seconds");
					if ($when < $limit) {
						$skip = 2;
						continue;
					}
				}
				if (substr($line, 0, 11) === 'ExitAddress') {
					$ip = explode(" ", $line)[1];
					if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) && !in_array($ip, $cache)) {
						$flag = true;
					}
				}
				if ($flag) {
					$result['ip'] = $ip;
					if ($extra) {
						$result['last_seen'] = $fullDate;
						$result['ts']=$now;
					}
					$cache[] = $result;
				}
			}
			return $cache;
		}
		return false;
	}

	public function parseSecOpsList ($cache = []) {
		$file = file_get_contents("https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst");
		if ($file) {
			$lines = preg_split('/\r\n|\r|\n/', $file);
			foreach ($lines as $line) {
				$ip = trim($line);
				if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) && !in_array($ip, $cache)) {
					$cache[] = $ip;
				}
			}
			return $cache;
		}
		return false;
	}

}
