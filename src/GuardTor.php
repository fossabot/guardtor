<?php
namespace GuardTor;
/*
	
	Title:        GuardTor
	Description:  GuardTor is a sophisticated PHP library for protecting your application against bad bots, scrappers, anonymous access from tor browsers, strong user input validations, prevent DDOS Attacks.
	Author:       Manomite LLC ( @manomite )
	Version:      1.0.0 / 2021
	License:      MIT
	For complete documentation, visit https://perishablepress.com/blackhole-bad-bots/
	
*/
use GuardTor\Limiter\Rate;
use GuardTor\Limiter\RedisRateLimiter;
use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\DeviceParserAbstract;

class GuardTor
{
    /**
     * Regular expression for matching and validating a MAC address
     * @var string
     */
    private $valid_mac = "([0-9A-F]{2}[:-]){5}([0-9A-F]{2})";
    /**
     * An array of valid MAC address characters
     * @var array
     */
    private $mac_address_vals = array(
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "A", "B", "C", "D", "E", "F"
     );
    //Data files for storing all data
    private $dataFiles = 'Data';
    //Create htaccess file to block bad bots
    //Default true
    public $createhtaccess = false;
    //Block all tor users
    //Default true
    public $blocktor = true;
    //Block Link to show to user once blocked
    public $blockLink = __DIR__.'/error.html';
    //Block All request greater than the requested limit
    //Default true
    public $block_request = true;
    //Requested limit per minute before blocking
    public $attempt = 100;

    /**
     * Init
     * @return void
     */
    public function __construct()
    {
        $this->projectDir = getcwd();
    }

    /**
     * Initialize GuardTor
     * @return void
     */
    public function init():void
    {
        if($this->createhtaccess){
            $this->createHtaccess();
        }
        $this->createDataFiles();
        $this->fetchTorDatabase();
        if($this->blocktor){
            $tor = $this->block_tor();
            if($tor === true){
                $this->redirect($this->blockLink);
            }
        }
        if($this->block_request){
            $request = $this->request_blocker();
            if($request === true){
                $this->redirect($this->blockLink);
            }
        }
    }
    /**
    * Redirection Handler
    * @var $link
    */
    private function redirect($link)
    {
        header('Location: '.$link);
    }
    /**
    * Create htaccess file for blocking bad bots
    * Only supports apache
    */
    private function createHtaccess():void
    {
        //Add apache security configurations.
        $fp = fopen($this->projectDir.'/.htaccess', 'a+');
        if ($fp) {
            fwrite($fp, $this->htaccessConfig());
        }
        fclose($fp);
    }
    /**
    * Creates all data files for application
    */
    private function createDataFiles():void
    {
        if (is_dir('src/'.$this->dataFiles)) {
            $files = array('blocked.dat', 'tordatabase.dat', 'cleanedtordatabase.dat');
            foreach ($files as $file) {
                if (file_exists('src/'.$this->dataFiles.'/'.$file)) {
                    //do nothing
                } else {
                    //create file
                    file_put_contents('src/'.$this->dataFiles.'/'.$file, '');
                }
            }
        } else {
            throw new \Exception('Data Directory is not present. Please create a Data directory in the src directory.');
        }
    }
    /**
    * Fetch Data from Tor exit addresses
    */
    private function fetchTorDatabase()
    {
        $update = false;
        $content = file_get_contents('src/'.$this->dataFiles.'/tordatabase.dat');
        if(!empty($content)){
            //Check last updated
            date_default_timezone_set('UTC');
            $lastModifiedTimestamp = filemtime('src/'.$this->dataFiles.'/tordatabase.dat');
            $time = time();
            $hours = $this->diffBtwTimesAsPerType($time, $lastModifiedTimestamp, 2);
            if($hours >= 1){
                $update = true;
            }
        }
        if ($update) {
            //Download Tor exit addresses
            $handle = fopen('https://check.torproject.org/exit-addresses', 'rb') or throw new \Exception("Could Not Open the specified Tor exit URl. It might be unavailable");
            $write = fopen('src/'.$this->dataFiles.'/tordatabase.dat', 'w');
            $buffer = "";
            while (!feof($handle)) {
                $buffer = fread($handle, 1024 * 1024);
                fwrite($write, $buffer);
            }
            fclose($handle);
            fclose($write);
            //Clean files for usage
            $this->prepareTorFile();
        }

    }
    private function diffBtwTimesAsPerType($start, $end, $returnType=1) {
        $seconds_diff = $start - $end;
        if($returnType == 1){
            return $seconds_diff/60;//minutes
        }else if($returnType == 2){
            return $seconds_diff/3600;//hours
        }else{
            return $seconds_diff/3600/24; //days
        }
    }
    /**
    * Prepare downloaded tor file and clean it for usage
    */
    private function prepareTorFile(){

        $fp = fopen('src/'.$this->dataFiles.'/tordatabase.dat', "r") or throw new \Exception("Error opening tor database");
        while ($line = fgets($fp)) {
            $explode = explode(" ", $line);
            if (substr_count($explode[1], '.') === 3 && $this->validate_ip($explode[1]) !== false) {
                //Store IP
                $this->fileTypewriter('src/'.$this->dataFiles.'/cleanedtordatabase.dat', $explode[1].PHP_EOL);
            }
        }
        fclose($fp);
    }
    /**
    * File writer
    * @var $filePath filepath to write to
    * @var $content file content
    */
    private function fileTypewriter($filePath, $content){
        $fp = fopen($filePath, 'a+');
        if ($fp) {
            fwrite($fp, $content);
        }
        fclose($fp);
    }
    /**
    * IP Validator
    * @var $ip Ip to validate
    */
    public function validate_ip($ip) {
	
        $options  = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        $filtered = filter_var($ip, FILTER_VALIDATE_IP, $options);
         if (!$filtered || empty($filtered)) {
            if (preg_match("/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/", $ip)) {
                return $ip; // IPv4 
            } elseif (preg_match("/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/", $ip)) { 
                return $ip; // IPv6 
            }
            return false;  
        }
        
        return $filtered;
    }
    /**
    * Block all tour request
    */
    private function block_tor()
    {
        $ip = $this->get_ip();
        $fp = fopen('src/'.$this->dataFiles.'/cleanedtordatabase.dat', "r") or throw new \Exception("Error opening tor file");
        while ($line = fgets($fp)) {
            if ($line[0] === $ip) {
                return true;
            }
        }
        fclose($fp);
        return false;
    }
    /**
    * Request Blocker (Requires Redis)
    */
    private function request_blocker()
    {
        $device = $this->getDeviceInfo();
        $fp = fopen('src/'.$this->dataFiles.'/blocked.dat', "r") or throw new \Exception("Error opening blocked file");
        while ($line = fgets($fp)) {
            $explode = explode(" ", $line);
            if ($device['fingerprint'] === $line[0]) {
                return true;
            }
        }
        fclose($fp);
        $rateLimiter = new RedisRateLimiter(new \Redis());
        $status = $rateLimiter->limitSilently($device['fingerprint'], Rate::perMinute($this->attempt));
        if ($status->getRemainingAttempts() === 0) {
            //Block Request
            date_default_timezone_set('UTC');
            $content = $device['fingerprint'].' '.$device['ip'].' '.$device['browser'].' '.$device['os'].' '.$device['device'].' '.date('d-m-Y/g:ia');
            $this->fileTypewriter('src/'.$this->dataFiles.'/blocked.dat', $content.PHP_EOL);
            return true;
        }
        return false;
    }
    /**
    * Get Device Info
    */
    public function getDeviceInfo():array{
        $ip = $this->get_ip();
        DeviceParserAbstract::setVersionTruncation(DeviceParserAbstract::VERSION_TRUNCATION_NONE);
        $userAgent = $this->strip($_SERVER['HTTP_USER_AGENT']);
        $dd = new DeviceDetector($userAgent);
        $dd->parse();
        $browsers = $dd->getClient();
        $browser = $browsers['name'].'/'.$browsers['version'];
        $osy = $dd->getOs();
        $device = $dd->getDeviceName();
        $os = $osy['name'].'/'.$osy['version'];

        //Get device fingerprint
        $linus = $this->getLinusMacAddress();
        $window = $this->getWinMacAddress();
        if($linus !== false){
            $fingerprint = (new Fingerprint())->codeGenerate($linus);
        } elseif($window !== false){
            $fingerprint = (new Fingerprint())->codeGenerate($window);
        } else {
            //Default
            $fingerprint = (new Fingerprint())->codeGenerate($browser.$device.$os);
        }
        $device = array(
            'fingerprint' => $fingerprint,
            'browser'     => $this->strip($browser),
            'os'          => $this->strip($os),
            'ip'          => $this->strip($ip),
            'device'      => $this->strip($device),
        );
        return $device;
    }
    /**
    * Get user IP address
    */
    public function get_ip():string {
        $ip = $this->evaluate_ip();
        if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $ip, $ip_match)) {
            $ip = $ip_match[1];
        }
        return $this->strip($ip);
    }
    /**
    * Evaluate IP Type
    */
    private function evaluate_ip() {
         
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_COMING_FROM', 'HTTP_PROXY_CONNECTION', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_COMING_FROM', 'HTTP_VIA', 'REMOTE_ADDR');
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    $ip = $this->normalize_ip($ip);
                    if ($this->validate_ip($ip)) {
                        return $ip; 
                    } 
                } 
            }   
        }
        return throw new \Exception('Error: Invalid Address');  
    }
    /**
    * IP Normalization
    * @var $ip IP to normalize
    */
    private function normalize_ip($ip) {
        if (strpos($ip, ':') !== false && substr_count($ip, '.') == 3 && strpos($ip, '[') === false) {
            // IPv4 with port (e.g., 123.123.123:80)
            $ip = explode(':', $ip);
            $ip = $ip[0]; 
        } else {
            // IPv6 with port (e.g., [::1]:80)
            $ip = explode(']', $ip);
            $ip = ltrim($ip[0], '[');  
        }
        return $ip; 
    }

    /**
     * Thanks to Adeyeye George for this function
     * Run the specified command and return it's output
     * @param string $command
     * @return string Output from command that was ran
     * @param string $type
     * @return string type of shell to use
     */
    private function runCommand($command, $type)
    {
        switch ($type) {
            case 'system':
                $shell = system($command);
                break;
            case 'shell_exec':
                $shell = shell_exec($command);
                break;
            case 'passthru':
                $code = passthru($command);
                break;
            default:
                $shell = exec($command);
        }
        return $shell;
    }

     /**
      * Thanks to Adeyeye George for this function
     * Get the linus system's current MAC address
     * @param string $interface The name of the interface e.g. eth0
     * @return string|bool Systems current MAC address; otherwise false on error
     */
    private function getLinusMacAddress()
    {
        $interface = 'eth0';
        $ifconfig = $this->runCommand("ifconfig {$interface}", 'shell_exec');
        preg_match("/" . $this->valid_mac . "/i", $ifconfig, $ifconfig);
        if (isset($ifconfig[0])) {
            return trim(strtoupper($ifconfig[0]));
        }
        return false;
    }
    /**
     * Thanks to Adeyeye George for this function
     * Get the windows system's current MAC address
     * @param string $interface The name of the interface e.g. all
     */
    private function getWinMacAddress()
    {
        $interface = 'all';
        $position = 'Physical Address';
        // Turn on output buffering
        ob_start();
        //Get the ipconfig details using system commond
        $this->runCommand("ipconfig /{$interface}", 'system');
        // Capture the output into a variable
        $mycom = ob_get_contents();
        // Clean (erase) the output buffer
        ob_clean();
        $findme = $position;
        //List of positions [Physical Address, IPv4, Description, DHCP Server, Subnet Mask, Default Gateway, Host Name]
        //Search the "Physical" | Find the position of Physical text
        $pmac = strpos($mycom, $findme);
        // Get Physical Address
        if ($mac = substr($mycom, ($pmac + 36), 17)) {
            //Display Mac Address
            return $mac;
        }
        return false;
    }
    /**
     * Clean all user inputs
     * @param string $value The string to be cleaned
     * @return string
     */
    public function strip($value)
    {
        if ($value === null) {
            return $value;
        }
        $data = strip_tags($value);
        $data = filter_var($data, FILTER_SANITIZE_STRING);
        $data = $this->cleanString($data);
        return $data;
    }
    /**
     * Clean html inputs
     * @param string $html The string to be cleaned
     * @return string
     */
    public function filterHtml($html)
    {
        $conf = \HTMLPurifier_Config::createDefault();
        $purifier = new \HTMLPurifier($conf);
        return $purifier->purify($html);
    }

    private function mbstring_binary_safe_encoding($reset = false)
    {
        static $encodings  = array();
        static $overloaded = null;
     
        if (is_null($overloaded)) {
            $overloaded = function_exists('mb_internal_encoding') && (ini_get('mbstring.func_overload') & 2); // phpcs:ignore PHPCompatibility.IniDirectives.RemovedIniDirectives.mbstring_func_overloadDeprecated
        }
     
        if (false === $overloaded) {
            return;
        }
     
        if (! $reset) {
            $encoding = mb_internal_encoding();
            array_push($encodings, $encoding);
            mb_internal_encoding('ISO-8859-1');
        }
     
        if ($reset && $encodings) {
            $encoding = array_pop($encodings);
            mb_internal_encoding($encoding);
        }
    }
    private function reset_mbstring_encoding()
    {
        $this->mbstring_binary_safe_encoding(true);
    }

    /**
     * Checks to see if a string is utf8 encoded.
     * NOTE: This function checks for 5-Byte sequences, UTF8 has Bytes Sequences with a maximum length of 4.
     * @param string $str The string to be checked
     * @return bool True if $str fits a UTF-8 model, false otherwise.
     */
    private function seems_utf8($str)
    {
        $this->mbstring_binary_safe_encoding();
        $length = strlen($str);
        $this->reset_mbstring_encoding();
        for ($i=0; $i < $length; $i++) {
            $c = ord($str[$i]);
            if ($c < 0x80) {
                $n = 0;
            } // 0bbbbbbb
            elseif (($c & 0xE0) == 0xC0) {
                $n=1;
            } // 110bbbbb
            elseif (($c & 0xF0) == 0xE0) {
                $n=2;
            } // 1110bbbb
            elseif (($c & 0xF8) == 0xF0) {
                $n=3;
            } // 11110bbb
            elseif (($c & 0xFC) == 0xF8) {
                $n=4;
            } // 111110bb
            elseif (($c & 0xFE) == 0xFC) {
                $n=5;
            } // 1111110b
            else {
                return false;
            } // Does not match any model
        for ($j=0; $j<$n; $j++) { // n bytes matching 10bbbbbb follow ?
            if ((++$i == $length) || ((ord($str[$i]) & 0xC0) != 0x80)) {
                return false;
            }
        }
        }
        return true;
    }

    /**
     * Function to clean a string so all characters with accents are turned into ASCII characters. EG: ‡ = a
     *
     * @param str $string
     * @return str
     */
    private function cleanString($string)
    {
        if (! preg_match('/[\x80-\xff]/', $string)) {
            return $string;
        }
    
        if ($this->seems_utf8($string)) {
            $chars = array(
                // Decompositions for Latin-1 Supplement.
                'ª' => 'a',
                'º' => 'o',
                'À' => 'A',
                'Á' => 'A',
                'Â' => 'A',
                'Ã' => 'A',
                'Ä' => 'A',
                'Å' => 'A',
                'Æ' => 'AE',
                'Ç' => 'C',
                'È' => 'E',
                'É' => 'E',
                'Ê' => 'E',
                'Ë' => 'E',
                'Ì' => 'I',
                'Í' => 'I',
                'Î' => 'I',
                'Ï' => 'I',
                'Ð' => 'D',
                'Ñ' => 'N',
                'Ò' => 'O',
                'Ó' => 'O',
                'Ô' => 'O',
                'Õ' => 'O',
                'Ö' => 'O',
                'Ù' => 'U',
                'Ú' => 'U',
                'Û' => 'U',
                'Ü' => 'U',
                'Ý' => 'Y',
                'Þ' => 'TH',
                'ß' => 's',
                'à' => 'a',
                'á' => 'a',
                'â' => 'a',
                'ã' => 'a',
                'ä' => 'a',
                'å' => 'a',
                'æ' => 'ae',
                'ç' => 'c',
                'è' => 'e',
                'é' => 'e',
                'ê' => 'e',
                'ë' => 'e',
                'ì' => 'i',
                'í' => 'i',
                'î' => 'i',
                'ï' => 'i',
                'ð' => 'd',
                'ñ' => 'n',
                'ò' => 'o',
                'ó' => 'o',
                'ô' => 'o',
                'õ' => 'o',
                'ö' => 'o',
                'ø' => 'o',
                'ù' => 'u',
                'ú' => 'u',
                'û' => 'u',
                'ü' => 'u',
                'ý' => 'y',
                'þ' => 'th',
                'ÿ' => 'y',
                'Ø' => 'O',
                // Decompositions for Latin Extended-A.
                'Ā' => 'A',
                'ā' => 'a',
                'Ă' => 'A',
                'ă' => 'a',
                'Ą' => 'A',
                'ą' => 'a',
                'Ć' => 'C',
                'ć' => 'c',
                'Ĉ' => 'C',
                'ĉ' => 'c',
                'Ċ' => 'C',
                'ċ' => 'c',
                'Č' => 'C',
                'č' => 'c',
                'Ď' => 'D',
                'ď' => 'd',
                'Đ' => 'D',
                'đ' => 'd',
                'Ē' => 'E',
                'ē' => 'e',
                'Ĕ' => 'E',
                'ĕ' => 'e',
                'Ė' => 'E',
                'ė' => 'e',
                'Ę' => 'E',
                'ę' => 'e',
                'Ě' => 'E',
                'ě' => 'e',
                'Ĝ' => 'G',
                'ĝ' => 'g',
                'Ğ' => 'G',
                'ğ' => 'g',
                'Ġ' => 'G',
                'ġ' => 'g',
                'Ģ' => 'G',
                'ģ' => 'g',
                'Ĥ' => 'H',
                'ĥ' => 'h',
                'Ħ' => 'H',
                'ħ' => 'h',
                'Ĩ' => 'I',
                'ĩ' => 'i',
                'Ī' => 'I',
                'ī' => 'i',
                'Ĭ' => 'I',
                'ĭ' => 'i',
                'Į' => 'I',
                'į' => 'i',
                'İ' => 'I',
                'ı' => 'i',
                'Ĳ' => 'IJ',
                'ĳ' => 'ij',
                'Ĵ' => 'J',
                'ĵ' => 'j',
                'Ķ' => 'K',
                'ķ' => 'k',
                'ĸ' => 'k',
                'Ĺ' => 'L',
                'ĺ' => 'l',
                'Ļ' => 'L',
                'ļ' => 'l',
                'Ľ' => 'L',
                'ľ' => 'l',
                'Ŀ' => 'L',
                'ŀ' => 'l',
                'Ł' => 'L',
                'ł' => 'l',
                'Ń' => 'N',
                'ń' => 'n',
                'Ņ' => 'N',
                'ņ' => 'n',
                'Ň' => 'N',
                'ň' => 'n',
                'ŉ' => 'n',
                'Ŋ' => 'N',
                'ŋ' => 'n',
                'Ō' => 'O',
                'ō' => 'o',
                'Ŏ' => 'O',
                'ŏ' => 'o',
                'Ő' => 'O',
                'ő' => 'o',
                'Œ' => 'OE',
                'œ' => 'oe',
                'Ŕ' => 'R',
                'ŕ' => 'r',
                'Ŗ' => 'R',
                'ŗ' => 'r',
                'Ř' => 'R',
                'ř' => 'r',
                'Ś' => 'S',
                'ś' => 's',
                'Ŝ' => 'S',
                'ŝ' => 's',
                'Ş' => 'S',
                'ş' => 's',
                'Š' => 'S',
                'š' => 's',
                'Ţ' => 'T',
                'ţ' => 't',
                'Ť' => 'T',
                'ť' => 't',
                'Ŧ' => 'T',
                'ŧ' => 't',
                'Ũ' => 'U',
                'ũ' => 'u',
                'Ū' => 'U',
                'ū' => 'u',
                'Ŭ' => 'U',
                'ŭ' => 'u',
                'Ů' => 'U',
                'ů' => 'u',
                'Ű' => 'U',
                'ű' => 'u',
                'Ų' => 'U',
                'ų' => 'u',
                'Ŵ' => 'W',
                'ŵ' => 'w',
                'Ŷ' => 'Y',
                'ŷ' => 'y',
                'Ÿ' => 'Y',
                'Ź' => 'Z',
                'ź' => 'z',
                'Ż' => 'Z',
                'ż' => 'z',
                'Ž' => 'Z',
                'ž' => 'z',
                'ſ' => 's',
                // Decompositions for Latin Extended-B.
                'Ș' => 'S',
                'ș' => 's',
                'Ț' => 'T',
                'ț' => 't',
                // Euro sign.
                '€' => 'E',
                // GBP (Pound) sign.
                '£' => '',
                // Vowels with diacritic (Vietnamese).
                // Unmarked.
                'Ơ' => 'O',
                'ơ' => 'o',
                'Ư' => 'U',
                'ư' => 'u',
                // Grave accent.
                'Ầ' => 'A',
                'ầ' => 'a',
                'Ằ' => 'A',
                'ằ' => 'a',
                'Ề' => 'E',
                'ề' => 'e',
                'Ồ' => 'O',
                'ồ' => 'o',
                'Ờ' => 'O',
                'ờ' => 'o',
                'Ừ' => 'U',
                'ừ' => 'u',
                'Ỳ' => 'Y',
                'ỳ' => 'y',
                // Hook.
                'Ả' => 'A',
                'ả' => 'a',
                'Ẩ' => 'A',
                'ẩ' => 'a',
                'Ẳ' => 'A',
                'ẳ' => 'a',
                'Ẻ' => 'E',
                'ẻ' => 'e',
                'Ể' => 'E',
                'ể' => 'e',
                'Ỉ' => 'I',
                'ỉ' => 'i',
                'Ỏ' => 'O',
                'ỏ' => 'o',
                'Ổ' => 'O',
                'ổ' => 'o',
                'Ở' => 'O',
                'ở' => 'o',
                'Ủ' => 'U',
                'ủ' => 'u',
                'Ử' => 'U',
                'ử' => 'u',
                'Ỷ' => 'Y',
                'ỷ' => 'y',
                // Tilde.
                'Ẫ' => 'A',
                'ẫ' => 'a',
                'Ẵ' => 'A',
                'ẵ' => 'a',
                'Ẽ' => 'E',
                'ẽ' => 'e',
                'Ễ' => 'E',
                'ễ' => 'e',
                'Ỗ' => 'O',
                'ỗ' => 'o',
                'Ỡ' => 'O',
                'ỡ' => 'o',
                'Ữ' => 'U',
                'ữ' => 'u',
                'Ỹ' => 'Y',
                'ỹ' => 'y',
                // Acute accent.
                'Ấ' => 'A',
                'ấ' => 'a',
                'Ắ' => 'A',
                'ắ' => 'a',
                'Ế' => 'E',
                'ế' => 'e',
                'Ố' => 'O',
                'ố' => 'o',
                'Ớ' => 'O',
                'ớ' => 'o',
                'Ứ' => 'U',
                'ứ' => 'u',
                // Dot below.
                'Ạ' => 'A',
                'ạ' => 'a',
                'Ậ' => 'A',
                'ậ' => 'a',
                'Ặ' => 'A',
                'ặ' => 'a',
                'Ẹ' => 'E',
                'ẹ' => 'e',
                'Ệ' => 'E',
                'ệ' => 'e',
                'Ị' => 'I',
                'ị' => 'i',
                'Ọ' => 'O',
                'ọ' => 'o',
                'Ộ' => 'O',
                'ộ' => 'o',
                'Ợ' => 'O',
                'ợ' => 'o',
                'Ụ' => 'U',
                'ụ' => 'u',
                'Ự' => 'U',
                'ự' => 'u',
                'Ỵ' => 'Y',
                'ỵ' => 'y',
                // Vowels with diacritic (Chinese, Hanyu Pinyin).
                'ɑ' => 'a',
                // Macron.
                'Ǖ' => 'U',
                'ǖ' => 'u',
                // Acute accent.
                'Ǘ' => 'U',
                'ǘ' => 'u',
                // Caron.
                'Ǎ' => 'A',
                'ǎ' => 'a',
                'Ǐ' => 'I',
                'ǐ' => 'i',
                'Ǒ' => 'O',
                'ǒ' => 'o',
                'Ǔ' => 'U',
                'ǔ' => 'u',
                'Ǚ' => 'U',
                'ǚ' => 'u',
                // Grave accent.
                'Ǜ' => 'U',
                'ǜ' => 'u',
            );

            $string = strtr($string, $chars);
        } else {
            $chars = array();
            // Assume ISO-8859-1 if not UTF-8.
            $chars['in'] = "\x80\x83\x8a\x8e\x9a\x9e"
                . "\x9f\xa2\xa5\xb5\xc0\xc1\xc2"
                . "\xc3\xc4\xc5\xc7\xc8\xc9\xca"
                . "\xcb\xcc\xcd\xce\xcf\xd1\xd2"
                . "\xd3\xd4\xd5\xd6\xd8\xd9\xda"
                . "\xdb\xdc\xdd\xe0\xe1\xe2\xe3"
                . "\xe4\xe5\xe7\xe8\xe9\xea\xeb"
                . "\xec\xed\xee\xef\xf1\xf2\xf3"
                . "\xf4\xf5\xf6\xf8\xf9\xfa\xfb"
                . "\xfc\xfd\xff";
    
            $chars['out'] = 'EfSZszYcYuAAAAAACEEEEIIIINOOOOOOUUUUYaaaaaaceeeeiiiinoooooouuuuyy';
    
            $string              = strtr($string, $chars['in'], $chars['out']);
            $double_chars        = array();
            $double_chars['in']  = array( "\x8c", "\x9c", "\xc6", "\xd0", "\xde", "\xdf", "\xe6", "\xf0", "\xfe" );
            $double_chars['out'] = array( 'OE', 'oe', 'AE', 'DH', 'TH', 'ss', 'ae', 'dh', 'th' );
            $string              = str_replace($double_chars['in'], $double_chars['out'], $string);
        }
    
        return $string;
    }
    /**
    * Htaccess configurations for preventing bad bots
    */
    private function htaccessConfig():string
    {
        return '
        #GuardTor Configurations (--DO NOT TOUCH HERE--)
        RewriteEngine on
        Options All -Indexes
        <FilesMatch "\.(htaccess|htpasswd|ini|psd|log|sh|xml|cgi|ini|lock)$">
        Order Allow,Deny
        Deny from all
        SetOutputFilter DEFLATE
        </FilesMatch>
        # Block Bad Bots & Scrapers
        SetEnvIfNoCase User-Agent "Aboundex" bad_bot
        SetEnvIfNoCase User-Agent "80legs" bad_bot
        SetEnvIfNoCase User-Agent "360Spider" bad_bot
        SetEnvIfNoCase User-Agent "^Java" bad_bot
        SetEnvIfNoCase User-Agent "^Cogentbot" bad_bot
        SetEnvIfNoCase User-Agent "^Alexibot" bad_bot
        SetEnvIfNoCase User-Agent "^asterias" bad_bot
        SetEnvIfNoCase User-Agent "^attach" bad_bot
        SetEnvIfNoCase User-Agent "^BackDoorBot" bad_bot
        SetEnvIfNoCase User-Agent "^BackWeb" bad_bot
        SetEnvIfNoCase User-Agent "Bandit" bad_bot
        SetEnvIfNoCase User-Agent "^BatchFTP" bad_bot
        SetEnvIfNoCase User-Agent "^Bigfoot" bad_bot
        SetEnvIfNoCase User-Agent "^Black.Hole" bad_bot
        SetEnvIfNoCase User-Agent "^BlackWidow" bad_bot
        SetEnvIfNoCase User-Agent "^BlowFish" bad_bot
        SetEnvIfNoCase User-Agent "^BotALot" bad_bot
        SetEnvIfNoCase User-Agent "Buddy" bad_bot
        SetEnvIfNoCase User-Agent "^BuiltBotTough" bad_bot
        SetEnvIfNoCase User-Agent "^Bullseye" bad_bot
        SetEnvIfNoCase User-Agent "^BunnySlippers" bad_bot
        SetEnvIfNoCase User-Agent "^Cegbfeieh" bad_bot
        SetEnvIfNoCase User-Agent "^CheeseBot" bad_bot
        SetEnvIfNoCase User-Agent "^CherryPicker" bad_bot
        SetEnvIfNoCase User-Agent "^ChinaClaw" bad_bot
        SetEnvIfNoCase User-Agent "Collector" bad_bot
        SetEnvIfNoCase User-Agent "Copier" bad_bot
        SetEnvIfNoCase User-Agent "^CopyRightCheck" bad_bot
        SetEnvIfNoCase User-Agent "^cosmos" bad_bot
        SetEnvIfNoCase User-Agent "^Crescent" bad_bot
        SetEnvIfNoCase User-Agent "^Custo" bad_bot
        SetEnvIfNoCase User-Agent "^AIBOT" bad_bot
        SetEnvIfNoCase User-Agent "^DISCo" bad_bot
        SetEnvIfNoCase User-Agent "^DIIbot" bad_bot
        SetEnvIfNoCase User-Agent "^DittoSpyder" bad_bot
        SetEnvIfNoCase User-Agent "^Download\ Demon" bad_bot
        SetEnvIfNoCase User-Agent "^Download\ Devil" bad_bot
        SetEnvIfNoCase User-Agent "^Download\ Wonder" bad_bot
        SetEnvIfNoCase User-Agent "^dragonfly" bad_bot
        SetEnvIfNoCase User-Agent "^Drip" bad_bot
        SetEnvIfNoCase User-Agent "^eCatch" bad_bot
        SetEnvIfNoCase User-Agent "^EasyDL" bad_bot
        SetEnvIfNoCase User-Agent "^ebingbong" bad_bot
        SetEnvIfNoCase User-Agent "^EirGrabber" bad_bot
        SetEnvIfNoCase User-Agent "^EmailCollector" bad_bot
        SetEnvIfNoCase User-Agent "^EmailSiphon" bad_bot
        SetEnvIfNoCase User-Agent "^EmailWolf" bad_bot
        SetEnvIfNoCase User-Agent "^EroCrawler" bad_bot
        SetEnvIfNoCase User-Agent "^Exabot" bad_bot
        SetEnvIfNoCase User-Agent "^Express\ WebPictures" bad_bot
        SetEnvIfNoCase User-Agent "Extractor" bad_bot
        SetEnvIfNoCase User-Agent "^EyeNetIE" bad_bot
        SetEnvIfNoCase User-Agent "^Foobot" bad_bot
        SetEnvIfNoCase User-Agent "^flunky" bad_bot
        SetEnvIfNoCase User-Agent "^FrontPage" bad_bot
        SetEnvIfNoCase User-Agent "^Go-Ahead-Got-It" bad_bot
        SetEnvIfNoCase User-Agent "^gotit" bad_bot
        SetEnvIfNoCase User-Agent "^GrabNet" bad_bot
        SetEnvIfNoCase User-Agent "^Grafula" bad_bot
        SetEnvIfNoCase User-Agent "^Harvest" bad_bot
        SetEnvIfNoCase User-Agent "^hloader" bad_bot
        SetEnvIfNoCase User-Agent "^HMView" bad_bot
        SetEnvIfNoCase User-Agent "^HTTrack" bad_bot
        SetEnvIfNoCase User-Agent "^humanlinks" bad_bot
        SetEnvIfNoCase User-Agent "^IlseBot" bad_bot
        SetEnvIfNoCase User-Agent "^Image\ Stripper" bad_bot
        SetEnvIfNoCase User-Agent "^Image\ Sucker" bad_bot
        SetEnvIfNoCase User-Agent "Indy\ Library" bad_bot
        SetEnvIfNoCase User-Agent "^InfoNaviRobot" bad_bot
        SetEnvIfNoCase User-Agent "^InfoTekies" bad_bot
        SetEnvIfNoCase User-Agent "^Intelliseek" bad_bot
        SetEnvIfNoCase User-Agent "^InterGET" bad_bot
        SetEnvIfNoCase User-Agent "^Internet\ Ninja" bad_bot
        SetEnvIfNoCase User-Agent "^Iria" bad_bot
        SetEnvIfNoCase User-Agent "^Jakarta" bad_bot
        SetEnvIfNoCase User-Agent "^JennyBot" bad_bot
        SetEnvIfNoCase User-Agent "^JetCar" bad_bot
        SetEnvIfNoCase User-Agent "^JOC" bad_bot
        SetEnvIfNoCase User-Agent "^JustView" bad_bot
        SetEnvIfNoCase User-Agent "^Jyxobot" bad_bot
        SetEnvIfNoCase User-Agent "^Kenjin.Spider" bad_bot
        SetEnvIfNoCase User-Agent "^Keyword.Density" bad_bot
        SetEnvIfNoCase User-Agent "^larbin" bad_bot
        SetEnvIfNoCase User-Agent "^LexiBot" bad_bot
        SetEnvIfNoCase User-Agent "^lftp" bad_bot
        SetEnvIfNoCase User-Agent "^libWeb/clsHTTP" bad_bot
        SetEnvIfNoCase User-Agent "^likse" bad_bot
        SetEnvIfNoCase User-Agent "^LinkextractorPro" bad_bot
        SetEnvIfNoCase User-Agent "^LinkScan/8.1a.Unix" bad_bot
        SetEnvIfNoCase User-Agent "^LNSpiderguy" bad_bot
        SetEnvIfNoCase User-Agent "^LinkWalker" bad_bot
        SetEnvIfNoCase User-Agent "^lwp-trivial" bad_bot
        SetEnvIfNoCase User-Agent "^LWP::Simple" bad_bot
        SetEnvIfNoCase User-Agent "^Magnet" bad_bot
        SetEnvIfNoCase User-Agent "^Mag-Net" bad_bot
        SetEnvIfNoCase User-Agent "^MarkWatch" bad_bot
        SetEnvIfNoCase User-Agent "^Mass\ Downloader" bad_bot
        SetEnvIfNoCase User-Agent "^Mata.Hari" bad_bot
        SetEnvIfNoCase User-Agent "^Memo" bad_bot
        SetEnvIfNoCase User-Agent "^Microsoft.URL" bad_bot
        SetEnvIfNoCase User-Agent "^Microsoft\ URL\ Control" bad_bot
        SetEnvIfNoCase User-Agent "^MIDown\ tool" bad_bot
        SetEnvIfNoCase User-Agent "^MIIxpc" bad_bot
        SetEnvIfNoCase User-Agent "^Mirror" bad_bot
        SetEnvIfNoCase User-Agent "^Missigua\ Locator" bad_bot
        SetEnvIfNoCase User-Agent "^Mister\ PiX" bad_bot
        SetEnvIfNoCase User-Agent "^moget" bad_bot
        SetEnvIfNoCase User-Agent "^Mozilla/3.Mozilla/2.01" bad_bot
        SetEnvIfNoCase User-Agent "^Mozilla.*NEWT" bad_bot
        SetEnvIfNoCase User-Agent "^NAMEPROTECT" bad_bot
        SetEnvIfNoCase User-Agent "^Navroad" bad_bot
        SetEnvIfNoCase User-Agent "^NearSite" bad_bot
        SetEnvIfNoCase User-Agent "^NetAnts" bad_bot
        SetEnvIfNoCase User-Agent "^Netcraft" bad_bot
        SetEnvIfNoCase User-Agent "^NetMechanic" bad_bot
        SetEnvIfNoCase User-Agent "^NetSpider" bad_bot
        SetEnvIfNoCase User-Agent "^Net\ Vampire" bad_bot
        SetEnvIfNoCase User-Agent "^NetZIP" bad_bot
        SetEnvIfNoCase User-Agent "^NextGenSearchBot" bad_bot
        SetEnvIfNoCase User-Agent "^NG" bad_bot
        SetEnvIfNoCase User-Agent "^NICErsPRO" bad_bot
        SetEnvIfNoCase User-Agent "^niki-bot" bad_bot
        SetEnvIfNoCase User-Agent "^NimbleCrawler" bad_bot
        SetEnvIfNoCase User-Agent "^Ninja" bad_bot
        SetEnvIfNoCase User-Agent "^NPbot" bad_bot
        SetEnvIfNoCase User-Agent "^Octopus" bad_bot
        SetEnvIfNoCase User-Agent "^Offline\ Explorer" bad_bot
        SetEnvIfNoCase User-Agent "^Offline\ Navigator" bad_bot
        SetEnvIfNoCase User-Agent "^Openfind" bad_bot
        SetEnvIfNoCase User-Agent "^OutfoxBot" bad_bot
        SetEnvIfNoCase User-Agent "^PageGrabber" bad_bot
        SetEnvIfNoCase User-Agent "^Papa\ Foto" bad_bot
        SetEnvIfNoCase User-Agent "^pavuk" bad_bot
        SetEnvIfNoCase User-Agent "^pcBrowser" bad_bot
        SetEnvIfNoCase User-Agent "^PHP\ version\ tracker" bad_bot
        SetEnvIfNoCase User-Agent "^Pockey" bad_bot
        SetEnvIfNoCase User-Agent "^ProPowerBot/2.14" bad_bot
        SetEnvIfNoCase User-Agent "^ProWebWalker" bad_bot
        SetEnvIfNoCase User-Agent "^psbot" bad_bot
        SetEnvIfNoCase User-Agent "^Pump" bad_bot
        SetEnvIfNoCase User-Agent "^QueryN.Metasearch" bad_bot
        SetEnvIfNoCase User-Agent "^RealDownload" bad_bot
        SetEnvIfNoCase User-Agent "Reaper" bad_bot
        SetEnvIfNoCase User-Agent "Recorder" bad_bot
        SetEnvIfNoCase User-Agent "^ReGet" bad_bot
        SetEnvIfNoCase User-Agent "^RepoMonkey" bad_bot
        SetEnvIfNoCase User-Agent "^RMA" bad_bot
        SetEnvIfNoCase User-Agent "Siphon" bad_bot
        SetEnvIfNoCase User-Agent "^SiteSnagger" bad_bot
        SetEnvIfNoCase User-Agent "^SlySearch" bad_bot
        SetEnvIfNoCase User-Agent "^SmartDownload" bad_bot
        SetEnvIfNoCase User-Agent "^Snake" bad_bot
        SetEnvIfNoCase User-Agent "^Snapbot" bad_bot
        SetEnvIfNoCase User-Agent "^Snoopy" bad_bot
        SetEnvIfNoCase User-Agent "^sogou" bad_bot
        SetEnvIfNoCase User-Agent "^SpaceBison" bad_bot
        SetEnvIfNoCase User-Agent "^SpankBot" bad_bot
        SetEnvIfNoCase User-Agent "^spanner" bad_bot
        SetEnvIfNoCase User-Agent "^Sqworm" bad_bot
        SetEnvIfNoCase User-Agent "Stripper" bad_bot
        SetEnvIfNoCase User-Agent "Sucker" bad_bot
        SetEnvIfNoCase User-Agent "^SuperBot" bad_bot
        SetEnvIfNoCase User-Agent "^SuperHTTP" bad_bot
        SetEnvIfNoCase User-Agent "^Surfbot" bad_bot
        SetEnvIfNoCase User-Agent "^suzuran" bad_bot
        SetEnvIfNoCase User-Agent "^Szukacz/1.4" bad_bot
        SetEnvIfNoCase User-Agent "^tAkeOut" bad_bot
        SetEnvIfNoCase User-Agent "^Teleport" bad_bot
        SetEnvIfNoCase User-Agent "^Telesoft" bad_bot
        SetEnvIfNoCase User-Agent "^TurnitinBot/1.5" bad_bot
        SetEnvIfNoCase User-Agent "^The.Intraformant" bad_bot
        SetEnvIfNoCase User-Agent "^TheNomad" bad_bot
        SetEnvIfNoCase User-Agent "^TightTwatBot" bad_bot
        SetEnvIfNoCase User-Agent "^Titan" bad_bot
        SetEnvIfNoCase User-Agent "^True_Robot" bad_bot
        SetEnvIfNoCase User-Agent "^turingos" bad_bot
        SetEnvIfNoCase User-Agent "^TurnitinBot" bad_bot
        SetEnvIfNoCase User-Agent "^URLy.Warning" bad_bot
        SetEnvIfNoCase User-Agent "^Vacuum" bad_bot
        SetEnvIfNoCase User-Agent "^VCI" bad_bot
        SetEnvIfNoCase User-Agent "^VoidEYE" bad_bot
        SetEnvIfNoCase User-Agent "^Web\ Image\ Collector" bad_bot
        SetEnvIfNoCase User-Agent "^Web\ Sucker" bad_bot
        SetEnvIfNoCase User-Agent "^WebAuto" bad_bot
        SetEnvIfNoCase User-Agent "^WebBandit" bad_bot
        SetEnvIfNoCase User-Agent "^Webclipping.com" bad_bot
        SetEnvIfNoCase User-Agent "^WebCopier" bad_bot
        SetEnvIfNoCase User-Agent "^WebEMailExtrac.*" bad_bot
        SetEnvIfNoCase User-Agent "^WebEnhancer" bad_bot
        SetEnvIfNoCase User-Agent "^WebFetch" bad_bot
        SetEnvIfNoCase User-Agent "^WebGo\ IS" bad_bot
        SetEnvIfNoCase User-Agent "^Web.Image.Collector" bad_bot
        SetEnvIfNoCase User-Agent "^WebLeacher" bad_bot
        SetEnvIfNoCase User-Agent "^WebmasterWorldForumBot" bad_bot
        SetEnvIfNoCase User-Agent "^WebReaper" bad_bot
        SetEnvIfNoCase User-Agent "^WebSauger" bad_bot
        SetEnvIfNoCase User-Agent "^Website\ eXtractor" bad_bot
        SetEnvIfNoCase User-Agent "^Website\ Quester" bad_bot
        SetEnvIfNoCase User-Agent "^Webster" bad_bot
        SetEnvIfNoCase User-Agent "^WebStripper" bad_bot
        SetEnvIfNoCase User-Agent "^WebWhacker" bad_bot
        SetEnvIfNoCase User-Agent "^WebZIP" bad_bot
        SetEnvIfNoCase User-Agent "Whacker" bad_bot
        SetEnvIfNoCase User-Agent "^Widow" bad_bot
        SetEnvIfNoCase User-Agent "^WISENutbot" bad_bot
        SetEnvIfNoCase User-Agent "^WWWOFFLE" bad_bot
        SetEnvIfNoCase User-Agent "^WWW-Collector-E" bad_bot
        SetEnvIfNoCase User-Agent "^Xaldon" bad_bot
        SetEnvIfNoCase User-Agent "^Xenu" bad_bot
        SetEnvIfNoCase User-Agent "^Zeus" bad_bot
        SetEnvIfNoCase User-Agent "ZmEu" bad_bot
        SetEnvIfNoCase User-Agent "^Zyborg" bad_bot
        
        #XSS
        Header set X-XSS-protection "1 mode=block"
        
        # Vulnerability Scanners
        SetEnvIfNoCase User-Agent "Acunetix" bad_bot
        SetEnvIfNoCase User-Agent "FHscan" bad_bot
        
        # Aggressive Chinese Search Engine
        SetEnvIfNoCase User-Agent "Baiduspider" bad_bot
        
        # Aggressive Russian Search Engine
        SetEnvIfNoCase User-Agent "Yandex" bad_bot
        
        
        <Limit GET POST HEAD>
        Order Allow,Deny
        Allow from all
        
        # Cyveillance
        deny from 38.100.19.8/29
        deny from 38.100.21.0/24
        deny from 38.100.41.64/26
        deny from 38.105.71.0/25
        deny from 38.105.83.0/27
        deny from 38.112.21.140/30
        deny from 38.118.42.32/29
        deny from 65.213.208.128/27
        deny from 65.222.176.96/27
        deny from 65.222.185.72/29
        
        Deny from env=bad_bot
        </Limit>';
    }
}