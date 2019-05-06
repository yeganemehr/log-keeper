#!/usr/local/php72/bin/php
<?php
error_reporting(E_ALL);
ini_set('display_errors', true);

if (in_array("install", $_SERVER['argv'])) {
	$content = "[Service]
Type=simple
ExecStart=" . realpath($_SERVER['PHP_SELF']) . "

[Install]
WantedBy=multi-user.target";
	file_put_contents("/etc/systemd/system/logkeeper.service", $content);
	shell_exec("systemctl enable logkeeper");
	echo ("To start the start run:\n\tsystemctl start logkeeper\n");
	exit(0);
}
class FileInfo {
	public $pos = 0;
	public $fp;
	public $lastUse;
}
class LogKeeper {
	const LOG_REGEX = '/^(?P<IP>\S+) (\S) (.*?) \[([^\]]+)\] "(?P<firstline>.+ .+)" ([0-9]+) ([0-9]+|-) "(.*)" "(?P<Agent>.*)"$/';
	
	private $dir;
	private $fd;
	private $wd;
	private $files;
	private $selfIPs = [];
	private $ips = [];
	private $lastReset;
	private $lastCloseFiles;
	private $blockedIPs = [];
	private $changeNginxConfig = false;
	private $lastRewriteNginxConfig = 0;
	public function __construct(string $dir) {
		$this->dir = $dir;
		$this->fd = inotify_init();
		$this->wd = inotify_add_watch($this->fd, $dir, IN_MODIFY);
		$this->selfIPs = file("/usr/local/directadmin/data/admin/ip.list", FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
		$this->lastReset = $this->lastCloseFiles = $this->lastRewriteNginxConfig = time();
		if (is_file("/etc/nginx/nginx-includes.conf") and stripos(file_get_contents("/etc/nginx/nginx-includes.conf"), "/etc/nginx/blocked-ips.conf") === false) {
			file_put_contents("/etc/nginx/nginx-includes.conf", "\ninclude /etc/nginx/blocked-ips.conf;", FILE_APPEND);
		}
		
	}
	public function __destruct() {
		inotify_rm_watch($this->fd, $this->wd);
		fclose($this->fd);
	}
	public function watch() {
		while (true) {
			$events = inotify_read($this->fd);
			foreach ($events as $event) {
				if (substr($event['name'], -4) == ".log" and substr($event['name'], -9) != "error.log") {
					$this->analizeFile($event['name']);
				}
			}
		}
	}

	private function analizeFile(string $file) {
		$now = time();
		if ($now - $this->lastReset > 60) {
			$this->lastReset = $now;
			$this->ips = [];
		}
		if (isset($this->files[$file])) {
			$info = $this->files[$file];
		} else {
			$info = new FileInfo();
			$info->fp = fopen($this->dir . "/" . $file, "r");
			fseek($info->fp, 0, SEEK_END);
			$info->pos = ftell($info->fp);
			$this->files[$file] = $info;
			return;
		}
		while (($line = stream_get_line($info->fp, 10 * 1024, "\n")) !== false) {
			$line = trim($line);
			if (!preg_match(self::LOG_REGEX, $line, $matches)) {
				error_log("line doesn't match in regex");
				var_dump($line);
				continue;
			}
			if ($this->isStaticFile($matches['firstline'])) {
				continue;
			}
			$this->recordConnectionCount($matches['IP']);
			if (!$this->isBlocked($matches['IP'])) {
				$reasonToBlock = "";
				$shouldBlock = null;
				if ($this->isGoogle($matches) or in_array($matches['IP'], $this->selfIPs)) {
					$shouldBlock = false;
				}
				if ($shouldBlock === null and $this->isBadBot($matches)) {
					$shouldBlock = true;
					$reasonToBlock = "User-Agent: {$matches['Agent']}";
				}

				if ($shouldBlock === null and $this->tooManyConnections($matches['IP'])) {
					$shouldBlock = true;
					$reasonToBlock = "Too many connetions: " . $this->ips[$matches['IP']];
				}
				
				if ($shouldBlock === true) {
					$this->block($matches['IP'], $reasonToBlock);
				}
			}
		}
		$info->lastUse = $now;
		$this->closeUnusedFiles();
		$this->rewriteNginxConfig();
	}
	private function block(string $ip, $reasonToBlock) {
		$now = time();
		if (!$this->isBlocked($ip)) {
			echo("Block IP ({$ip}): " . $reasonToBlock . "\n");
			$this->blocked[$ip] = $now + 3600;
			$this->changeNginxConfig = true;
			// echo shell_exec("csf -td {$ip} 3600")."\n";
		}
	}
	private function isGoogle($log): bool {
		return stripos($log['Agent'], "googlebot");
	}
	private function isBadBot($log): bool {
		$bads = array(
			'X11; Ubuntu; Linux x86_64; rv:62.0',
			'SemrushBot',
			'HeadlessChrome'
		);
		foreach ($bads as $bad) {
			if (stripos($log['Agent'], $bad) !== false) {
				return true;
			}
		}
		return false;
	}
	private function recordConnectionCount(string $ip) {
		if (isset($this->ips[$ip])) {
			$this->ips[$ip]++;
		} else {
			$this->ips[$ip] = 1;
		}
	}
	private function tooManyConnections(string $ip): bool {
		return (isset($this->ips[$ip]) and $this->ips[$ip] >= 100);
	}
	private function closeUnusedFiles() {
		$now = time();
		if ($now - $this->lastCloseFiles > 120) {
			foreach ($this->files as $file => $finfo) {
				if ($now - $finfo->lastUse > 120) {
					fclose($finfo->fp);
					unset($this->files[$file]);
				}
			}
			$this->lastCloseFiles = $now;
		}
	}
	private function rewriteNginxConfig() {
		if (!$this->changeNginxConfig) {
			return;
		}
		$now = time();
		if ($now - $this->lastRewriteNginxConfig > 120) {
			$fp = fopen("/etc/nginx/blocked-ips.conf", "w");
			foreach ($this->blocked as $ip => $expire) {
				if ($now - $expire < 0) {
					fwrite($fp, "deny {$ip};\n");
				} else {
					unset($this->blocked[$ip]);
				}
			}
			fclose($fp);
			shell_exec("nginx -s reload")."\n";
			$this->changeNginxConfig = false;
			$this->lastRewriteNginxConfig = time();
		}
	}
	private function isBlocked(string $ip): bool {
		return (isset($this->blocked[$ip]) and $this->blocked[$ip] - time() > 0);
	}
	private function isStaticFile(string $firstline): bool {
		$firstline = explode(" ", $firstline, 3);
		$url = $firstline[1];
		$url = parse_url($url,  PHP_URL_PATH);
		$dot = strrpos($url, ".");
		if ($dot === false) {
			return false;
		}
		$ext = substr($url, $dot + 1);
		return in_array($ext, ["jpg", "png", "gif", "tff", "woff", "woff2", "eot", "css", "js", "map", "json", "jpeg", "svg", "mp3", "mp4", "mkv", "ico"]);
	}
}

$keeper = new LogKeeper("/var/log/nginx/domains");
$keeper->watch();
