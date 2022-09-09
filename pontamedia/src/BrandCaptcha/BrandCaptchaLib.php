<?php 

namespace BrandCaptcha;

/**
 * @package   BrandCaptcha
 * @author    José Ramírez <jramirez@pontamedia.com>
 * @version   1.0.0
 * @copyright Copyright (c) 2016, PontaMedia.
 * @link      http://www.pontamedia.com/en/brandCaptcha
 *
 * This is a PHP library that handles calling BrandCaptcha.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
class BrandCaptchaResponse
{
  private $isValid;

  private $error;

  public function __construct() {
    $this->isValid = true;
  }

  public function setIsValid($isValid) {
    $this->isValid = $isValid;

    return $this;
  }

  public function getIsValid() {
    return $this->isValid;
  }

  public function setError($error) {
    $this->error = $error;
    $this->isValid = false;

    return $this;
  }

  public function getError() {
    return $this->error;
  }
}

class BrandCaptchaLib
{
  /**
   * Version of this client library.
   *
   * @const string
   */
  const VERSION = 'php_1.0.0';

  /**
   * Api host of brandcaptcha
   *
   * @const string
   */
  const API_HOST = 'api.ponta.co';

  /**
   * Api verify path of brandcaptcha
   *
   * @const string
   */
  const VERIFY_PATH = '/verify.php';

  /**
   * Api challenge path of brandcaptcha
   *
   * @const string
   */
  const CHALLENGE_PATH = '/challenge.php';

  /**
   * Qsencode
   *
   * @param array $data
   * @return string
   */
  private function brandcaptchaQsencode(array $data) {
    $req = "";
    
    foreach ($data as $key => $value)
      $req .= $key . '=' . urlencode(stripslashes($value)) . '&';

    // Cut the last '&'
    $req = substr($req,0,strlen($req)-1);
    
    return $req;
  }

  /**
   * Submits an HTTP POST to a BrandCaptcha server
   *
   * @param string $host
   * @param string $path
   * @param array $data
   * @param int port
   * @return array response
   */
  private function brandcaptchaHttpPost($host, $path, $data, $port = 80) {
    $response = '';
    $req = $this->brandcaptchaQsencode($data);

    $http_request  = "POST $path HTTP/1.0\r\n";
    $http_request .= "Host: $host\r\n";
    $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
    $http_request .= "Content-Length: " . strlen($req) . "\r\n";
    $http_request .= "User-Agent: brandcaptcha/PHP\r\n";
    $http_request .= "\r\n";
    $http_request .= $req;

    if (false == ($fs = @fsockopen(gethostbyname($host), $port, $errno, $errstr, 10))) {
      echo "$errstr ($errno)<br />\n";
      die ('Could not open socket');
    }

    fwrite($fs, $http_request);

    while (!feof($fs))
      $response .= fgets($fs, 1160); // One TCP-IP packet
    
    fclose($fs);
    
    $response = explode("\r\n\r\n", $response, 2);

    return $response;
  }

  /**
   * Gets the challenge HTML (javascript).
   * This is called from the browser, and the resulting BrandCaptcha HTML widget
   * is embedded within the HTML form it was called from.
   *
   * @param string $pubkey A public key for BrandCaptcha
   * @param string $error The error given by BrandCaptcha (optional, default is null)
   * @return string - The HTML to be embedded in the user's form.
   */
  public function brandcaptchaGetHtml($pubkey, $error = null) {
    $errorpart = "";

    if ($pubkey == null || $pubkey == '') {
      die ("To use BrandCaptcha you must get an API Key");
    }

    $server = "//". self::API_HOST . self::CHALLENGE_PATH;
    
    if ($error) {
      $errorpart = "&amp;error=" . $error;
    }

    return '<script type="text/javascript" src="'. $server . '?k=' . $pubkey . $errorpart . '"></script>';
  }

  /**
    * Calls an HTTP POST function to verify if the user's guess was correct
    *
    * @param string $privkey
    * @param string $remoteip
    * @param string $challenge
    * @param string $response
    * @param array $extra_params an array of extra variables to post to the server
    * @return BrandCaptchaResponse
    */
  public function brandcaptchaCheckAnswer($privkey, $remoteip, $challenge, $response, array $extra_params = array()) {
    $bcResponse = new BrandCaptchaResponse();
    $data = $extra_params;
    $data['privatekey'] = $privkey;
    $data['remoteip'] = $remoteip;
    $data['challenge'] = $challenge;

    if ($privkey == null || $privkey == '') {
      die ("To use BrandCaptcha you must get an API key");
    }

    if ($remoteip == null || $remoteip == '') {
      die ("For security reasons, you must pass the remote ip to BrandCaptcha");
    }
    
    //discard spam submissions
    if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0) {
      return $bcResponse->setError('incorrect-captcha-sol');
    }

    $data['response'] = $response;

    $response = $this->brandcaptchaHttpPost(
      self::API_HOST, 
      self::VERIFY_PATH,
      $data
    );

    $answers = explode("\n", $response[1]);

    if (trim ($answers[0]) != 'true') {
      return $bcResponse->setError($answers[1]);
    }

    return $bcResponse->setIsValid(true);
  }
}
