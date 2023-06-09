<?php

namespace TorUtils;

use Symfony\Component\Validator\Constraints\DateTime;

class TorUtils {

	public $options = [
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_CONNECTTIMEOUT => 10,
	];

	public $window = 21600;
	public $enableOnioo = true;
	public $enableTorExits = false;
	public $enableSecOpsList = false;

	public function __construct($userAgent) {
		$this->options[CURLOPT_USERAGENT] = $userAgent;
	}

	public function fetch($withTime = false) {
		$all = [];
		if ($this->enableOnioo) {
			$onioo = $this->parseOniooList($all);
			if ($onioo) {
				if ($withTime) {
					$now = new DateTime('now');
					foreach ($onioo as $each) {
						$all[] = ['ip'=>$each,'ts'=>$now];
					}
				} else {
					foreach ($onioo as $each) {
						$all[] = ['ip'=>$each];
					}
				}
				#$all = $this->formatList($all, $onioo, $withTime);
			}
		}
		if ($this->enableTorExits) {
			$torExits = $this->parseTorExitList($all);
			if ($torExits) {
				$all = $this->formatList($all, $torExits, $withTime);
			}
		}
		if ($this->enableSecOpsList) {
			$secOps = $this->parseSecOpsList($all);
			if ($secOps) {
				$all = $this->formatList($all, $secOps, $withTime);
			}
		}
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

	public function parseOniooList($cache = []) {
		$relays = $this->fetchOniooRelays();
		if (!$relays) {
			return false;
		}
		$now = time();
		foreach ($relays as $relay) {
			if (strtotime($relay['last_seen']) < $now - $this->window) {
				# Relay was last seen before our search window. Skip.
				continue;
			}
			if (in_array("Exit", $relay['flags'])) {
				foreach ($relay['or_addresses'] as $ip) {
					if (strpos($ip, ':') !== false) {
						// ipv6
						if(count(explode(':', $ip)) > 2 && strpos($ip, '[') !== false) {
							$cache[] = parse_url('http://'.$ip, PHP_URL_HOST);
						} elseif(count(explode(':', $ip)) === 2) {
							$cache[] = strstr( $ip, ':', true );
						}
					}
				}
			}
		}
		return $cache;
	}

	public function fetchOniooRelays() {
		$curl = curl_init("https://onionoo.torproject.org/details?fields=relays,flags,or_addresses,last_seen");
		curl_setopt_array($curl, $this->options);
		$response_raw = curl_exec($curl);
		if ($response_raw) {
			$response = json_decode($response_raw, true);
			return $response['relays'];
		} else {
			return false;
		}
	}

	public function parseTorExitList($cache = []) {
		$file = file_get_contents("https://check.torproject.org/exit-addresses");
		if ($file) {
			$lines = preg_split('/\r\n|\r|\n/', $file);
			foreach ($lines as $line) {
				if ($skip > 0) {
					$skip--;
					continue;
				}
				if (substr($line, 0, 10) === 'LastStatus') {
					$date = explode(" ", $line);
					$when = new DateTime($date[1].' '.$date[2]);
					$limit = new DateTime("-".$this->window." seconds");
					if ($when < $limit) {
						$skip = 2;
						continue;
					}
				}
				if (substr($line, 0, 11) === 'ExitAddress') {
					$ip = explode(" ", $line)[1];
					if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) && !in_array($ip, $cache)) {
						$cache[] = $ip;
					}
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
