#!/usr/local/php72/bin/php
<?php
error_reporting(E_ALL);
ini_set('display_errors', true);
$disabledFunctions = ini_get("disable_functions");
if (stripos($disabledFunctions, "shell_exec") !== false) {
	echo "shell_exec is disabled";
	exit(1);
}
if (in_array("install", $_SERVER['argv'])) {
	if (!extension_loaded("inotify") and in_array("inotify", $_SERVER['argv'])) {
		if ($disabledFunctions) {
			$ini = php_ini_loaded_file();
			$contentOrginal = file_get_contents($ini);
			$content = preg_replace("/^disable_functions\s*=/m", ";$0", $contentOrginal);
			file_put_contents($ini, $content);
		}
		$pecl = "/usr/local/php72/bin/pecl";
		echo "# {$pecl} install inotify\n";
		echo shell_exec("{$pecl} install inotify");
		if (isset($ini, $contentOrginal)) {
			file_put_contents($ini, $contentOrginal);
		}
		$inis = array_map("trim", explode(",", php_ini_scanned_files()));
		if (isset($inis[0]) and $inis[0]) {
			$dir = dirname($inis[0]);
			if (is_dir($dir)) {
				file_put_contents($dir . "/50-inotify.ini", "extension=inotify.so");
			}
		}
	}
	$content = "[Service]
Type=simple
ExecStart=/usr/local/php72/bin/php -d disable_functions " . realpath($_SERVER['PHP_SELF']) . "

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
	const LOG_REGEX = '/^(?P<IP>\S+) (\S) (.*?) \[([^\]]+)\] "(?P<firstline>.+ .+)" (?P<httpCode>[0-9]+) ([0-9]+|-) "(.*)" "(?P<Agent>.*)"$/';
	
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
	private $fpmErrors = [];
	public function __construct(string $dir) {
		$this->dir = $dir;
		if (!extension_loaded("inotify")) {
			error_log("inotify is not running");
			exit(1);
		}
		$this->fd = inotify_init();
		$this->wd = inotify_add_watch($this->fd, $dir, IN_MODIFY);
		$this->selfIPs = file("/usr/local/directadmin/data/admin/ip.list", FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
		$this->lastReset = $this->lastCloseFiles = $this->lastRewriteNginxConfig = time();
		if (is_file("/etc/nginx/nginx-includes.conf") and stripos(file_get_contents("/etc/nginx/nginx-includes.conf"), "/etc/nginx/blocked-ips.conf") === false) {
			file_put_contents("/etc/nginx/nginx-includes.conf", "\ninclude /etc/nginx/blocked-ips.conf;", FILE_APPEND);
		}
		
	}
	public function __destruct() {
		if ($this->wd) {
			inotify_rm_watch($this->fd, $this->wd);
		}
		if ($this->fd) {
			fclose($this->fd);
		}
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
		$log = Log::getInstance();
		$now = time();
		if ($now - $this->lastReset > 60) {
			$log->debug("reset ips and fpm errors after " . ($now - $this->lastReset) . " seconds");
			$this->lastReset = $now;
			$this->ips = [];
			$this->fpmErrors = [];
			$this->checkLogSize();
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
				$log->error("line doesn't match in regex");
				$log->reply($line);
				error_log("line doesn't match in regex");
				var_dump($line);
				continue;
			}
			if (in_array($matches['httpCode'], [502, 504])) {
				$log->debug("check fpm, http code: {$matches['httpCode']}");
				$this->checkFPM($matches['httpCode']);
			}
			if ($this->isStaticFile($matches['firstline'])) {
				$log->debug("static file, skip");
				continue;
			}
			if ($this->isAdminRequest($matches['firstline'])) {
				$log->debug("admin request, skip");
				continue;
			}
			if (in_array($matches['httpCode'], [500, 502, 503, 504, 403])) {
				$log->debug("http code: {$matches['httpCode']}, skip");
				continue;
			}
			if ($matches['IP'] == "164.132.141.251") {
				$log->debug("IP: {$matches['IP']}, skip");
				continue;
			}
			$this->recordConnectionCount($matches['IP']);
			if (!$this->isBlocked($matches['IP'])) {
				$reasonToBlock = "";
				$shouldBlock = null;
				if ($this->isGoogle($matches)) {
					$log->debug("Google, skip");
					continue;
				}
				if (in_array($matches['IP'], $this->selfIPs)) {
					$log->debug("Local ip: {$matches['IP']}, skip");
					continue;
				}
				if ($this->isBadBot($matches)) {
					$shouldBlock = true;
					$reasonToBlock = "User-Agent: {$matches['Agent']}";
				}

				if ($shouldBlock === null and $this->tooManyConnections($matches['IP'])) {
					$shouldBlock = true;
					$reasonToBlock = "Too many connetions: " . $this->ips[$matches['IP']];
				}
				
				if ($shouldBlock === true) {
					$log->info("ip: {$matches['IP']}, {$reasonToBlock}, block");
					$this->block($matches['IP'], $reasonToBlock);
				}
			} else {
				$log->debug("already blocked: {$matches['IP']}, skip");
			}
		}
		$info->lastUse = $now;
		$this->closeUnusedFiles();
		$this->rewriteNginxConfig();
	}
	private function block(string $ip, $reasonToBlock) {
		$now = time();
		if (!$this->isBlocked($ip)) {
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
			'HeadlessChrome',
			'sogou',
			'DuckDuckBot',
			'DotBot',
			'Yandex',
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
		$log = Log::getInstance();
		if (!$this->changeNginxConfig) {
			return;
		}
		$now = time();
		if ($now - $this->lastRewriteNginxConfig > 120) {
			$log->debug("rewrite nginx blocked ips");
			$fp = fopen("/etc/nginx/blocked-ips.conf", "w");
			foreach ($this->blocked as $ip => $expire) {
				if ($now - $expire < 0) {
					fwrite($fp, "deny {$ip};\n");
				} else {
					unset($this->blocked[$ip]);
				}
			}
			fclose($fp);
			$log->info("nginx -s reload");
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
	private function isAdminRequest(string $firstline): bool {
		$firstline = explode(" ", $firstline, 3);
		$url = $firstline[1];
		$url = parse_url($url,  PHP_URL_PATH);
		return preg_match("/^\/wp-admin\//i", $url);
	}
	private function checkFPM(int $statusCode): void {
		if (!isset($this->fpmErrors[$statusCode])) {
			$this->fpmErrors[$statusCode] = 0;
		}
		$this->fpmErrors[$statusCode]++;
		if ($this->fpmErrors[$statusCode] > 10) {
			$this->resetFPM();
		}
	}
	private function resetFPM() {
		$log = Log::getInstance();
		$log->info("service php-fpm72 restart");
		shell_exec("service php-fpm72 restart");
		$log->info("service php-fpm56 restart");
		shell_exec("service php-fpm56 restart");
		$this->fpmErrors = [];
	}
	private function checkLogSize() {
		$log = Log::getInstance();
		$log->info("get log size");
		$file = Log::getFile();
		if (!is_file($file)) {
			return;
		}
		$mb = round(filesize($file) / 1024 / 1024, 2);
		$log->reply($mb . " MB");
		if ($mb > 100) {
			$output = $file . "-" . time() . ".gz";
			$log->info("compress to {$output}");
			shell_exec("gzip -9 -c {$file} > " . $output);
			unlink($file);
		}
	}
}

class Log {
	const debug = 1;
	const info = 2;
	const warn = 3;
	const error = 4;
	const fatal = 6;
	const off = 0;
	static public $quiet = true;
	static private $parent;
	static protected $file;
	static private $generation = 0;
	static private $indentation = "\t";
	public static function newChild(){
		self::$generation++;
	}
	public static function dieChild(){
		self::$generation--;
	}
	public static function getParent(){
		if(!self::$parent){
			self::$parent = self::getInstance();
		}
		return self::$parent;
	}
	public static function getInstance(){
		$level = self::off;
		if (self::$parent) {
			$level = self::$parent->getLevel();
		}
		return new LogInstance($level);
	}
	public static function setFile($file){
		self::$file = $file;
	}
	public static function getFile(){
		return self::$file;
	}
	public static function setLevel($level){
		switch(strtolower($level)){
			case('debug'):$level = self::debug;break;
			case('info'):$level = self::info;break;
			case('warn'):$level = self::warn;break;
			case('error'):$level = self::error;break;
			case('fatal'):$level = self::fatal;break;
			case('off'):$level = self::off;break;
		}
		self::getParent()->setLevel($level);
	}
	public static function debug(){
		return call_user_func_array(array(self::getParent(),'debug'), func_get_args());
	}
	public static function info(){
		return call_user_func_array(array(self::getParent(),'info'), func_get_args());
	}
	public static function warn(){
		return call_user_func_array(array(self::getParent(),'warn'), func_get_args());
	}
	public static function error(){
		return call_user_func_array(array(self::getParent(),'error'), func_get_args());
	}
	public static function fatal(){
		return call_user_func_array(array(self::getParent(),'fatal'), func_get_args());
	}
	public static function append(){
		return call_user_func_array(array(self::getParent(),'append'), func_get_args());
	}
	public static function reply(){
		return call_user_func_array(array(self::getParent(),'reply'), func_get_args());
	}
	public static function setIndentation(string $indentation,int $repeat = 1){
		self::$indentation = str_repeat($indentation,$repeat);
	}
	public static function write($level, $message){
		$microtime = explode(" ",microtime());
		$date = date("Y-m-d H:i:s.".substr($microtime[0],2)." P");
		$levelText = '';
		switch($level){
			case(self::debug):$levelText = '[DEBUG]';break;
			case(self::info):$levelText = '[INFO]';break;
			case(self::warn):$levelText = '[WARN]';break;
			case(self::error):$levelText = '[ERROR]';break;
			case(self::fatal):$levelText = '[FATAL]';break;
		}
		$line = $date." ".$levelText.(self::$generation > 1 ? str_repeat(self::$indentation, self::$generation-1) : ' ').$message."\n";
		if (self::$quiet == 0) {
			echo $line;
		}
		file_put_contents(self::$file, $line, is_file(self::$file) ? FILE_APPEND : 0);
	}
}
class LogInstance {
	protected $level;
	protected $lastLevel;
	protected $lastMessage;
	protected $closed = false;
	protected $replyCharacter = '';
	protected $append = false;
	public function __construct($level){
		Log::newChild();
		$this->setLevel($level);
	}
	public function __destruct(){
		$this->end();
	}
	public function end(){
		if(!$this->closed){
			$this->closed = true;
			Log::dieChild();
		}
	}
	public function setLevel($level){
		if(in_array($level, array(
			Log::debug,
			Log::info,
			Log::warn,
			Log::error,
			Log::fatal,
			Log::off,
		))){
			$this->level = $level;
		}
	}
	public function getLevel(){
		return $this->level;
	}
	public function debug(){
		return $this->log(Log::debug,func_get_args());
	}
	public function info(){
		return $this->log(Log::info,func_get_args());
	}
	public function warn(){
		return $this->log(Log::warn,func_get_args());
	}
	public function error(){
		return $this->log(Log::error,func_get_args());
	}
	public function fatal(){
		return $this->log(Log::fatal,func_get_args());
	}
	public function log($level, $data){
		if($data){
			$check = $this->checkLevel($level);
			$this->lastLevel = $level;
			if($check){
				Log::write($level, $this->createMessage($data));
			}
			$this->append = false;
			$this->replyCharacter = '';
		}
		return $this;
	}
	public function append(){
		$this->replyCharacter = '';
		$this->append = true;
		return $this->log($this->lastLevel, func_get_args());
	}
	public function reply(){
		$this->replyCharacter = ': ';
		$this->append = true;
		return $this->log($this->lastLevel, func_get_args());
	}
	private function checkLevel($level){
		return($this->level and $level >= $this->level);
	}
	private function createMessage($args){
		$message = '';
		foreach($args as $arg){
			if($message){
				$message .= " ";
			}
			$type = gettype($arg);
			if(in_array($type, array('array','object','boolean','NULL'))){
			    if($type == 'object'){
			        $arg = (array)$arg;
			    }
				$message .= json_encode($arg);
			}else{
				$message .= $arg;
			}
		}
		if($this->append){
			$message = $this->lastMessage.$this->replyCharacter.$message;
		}
		$this->lastMessage = $message;
		return $message;
	}
}



Log::$quiet = false;
Log::setFile("/var/log/log-keeper.log");
Log::setLevel(Log::debug);
$keeper = new LogKeeper("/var/log/nginx/domains");
$keeper->watch();
