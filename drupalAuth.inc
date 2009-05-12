<?php

/*

Drupal extauth script for ejabberd.
Created by Tom MacWright of DevelopmentSeed (tom@developmentseed.com)

Copyright (c) <2005> LISSY Alexandre, "lissyx" <alexandrelissy@free.fr>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software andassociated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to thefollowing conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

class JabberAuth {
  var $dbhost; /* MySQL server */
  var $dbuser; /* MySQL user */
  var $dbpass; /* MySQL password */
  var $dbbase; /* MySQL database where users are stored */
  var $hash = 'sha256';

  var $debug    = true;               /* Debug mode */
  var $debugfile  = "/tmp/ejabberd-debug.log";  /* Debug output */
  var $logging  = true;              /* Do we log requests ? */
  var $logfile  = "/tmp/ejabberd-log.log" ;   /* Log file ... */
  /*
   * For both debug and logging, ejabberd have to be able to write.
   */
  
  var $jabber_user;   /* This is the jabber user passed to the script. filled by $this->command() */
  var $jabber_pass;   /* This is the jabber user password passed to the script. filled by $this->command() */
  var $jabber_server; /* This is the jabber server passed to the script. filled by $this->command(). Useful for VirtualHosts */
  var $jid;           /* Simply the JID, if you need it, you have to fill. */
  var $data;          /* This is what SM component send to us. */
    
  var $dateformat = "M d H:i:s"; /* Check date() for string format. */
  var $command; /* This is the command sent ... */
  var $mysock;  /* MySQL connection ressource */
  var $stdin;   /* stdin file pointer */
  var $stdout;  /* stdout file pointer */

  function JabberAuth()
  {
    @define_syslog_variables();
    @openlog("pipe-auth", LOG_NDELAY, LOG_SYSLOG);
    
    if($this->debug) {
      @error_reporting(E_ALL);
      @ini_set("log_errors", "1");
      @ini_set("error_log", $this->debugfile);
    }
    $this->logg("Starting pipe-auth ..."); // We notice that it's starting ...
    $this->openstd();
  }
  
  function stop()
  {
    $this->logg("Shutting down ..."); // Sorry, have to go ...
    closelog();
    $this->closestd(); // Simply close files
    exit(0); // and exit cleanly
  }
  
  function openstd()
  {
    $this->stdout = @fopen("php://stdout", "w"); // We open STDOUT so we can read
    $this->stdin  = @fopen("php://stdin", "r"); // and STDIN so we can talk !
  }
  
  function readstdin()
  {
    $l      = @fgets($this->stdin, 3); // We take the length of string
    $length = @unpack("n", $l); // ejabberd give us something to play with ...
    $len    = $length["1"]; // and we now know how long to read.
    if($len > 0) { // if not, we'll fill logfile ... and disk full is just funny once
      $this->logg("Reading $len bytes ... "); // We notice ...
      $data   = @fgets($this->stdin, $len+1);
      // $data = iconv("UTF-8", "ISO-8859-15", $data); // To be tested, not sure if still needed.
      $this->data = $data; // We set what we got.
      $this->logg("IN: ".$data);
    }
  }
  
  function closestd()
  {
    @fclose($this->stdin); // We close everything ...
    @fclose($this->stdout);
  }
  
  function out($message)
  {
    @fwrite($this->stdout, $message); // We reply ...
    $dump = @unpack("nn", $message);
    $dump = $dump["n"];
    $this->logg("OUT: ". $dump);
  }
  
  function myalive()
  {
    if(!is_resource($this->mysock) || !@mysql_ping($this->mysock)) { // check if we have a MySQL connection and if it's valid.
      $this->mysql(); // We try to reconnect if MySQL gone away ...
      return @mysql_ping($this->mysock); // we simply try again, to be sure ...
    } else {
      return true; // so good !
    }
  }
  
  function play()
  {
    do {
      $this->readstdin(); // get data
      $length = strlen($this->data); // compute data length
      if($length > 0 ) { // for debug mainly ...
        $this->logg("GO: ".$this->data);
        $this->logg("data length is : ".$length);
      }
      $ret = $this->command(); // play with data !
      $this->logg("RE: " . $ret); // this is what WE send.
      $this->out($ret); // send what we reply.
      $this->data = NULL; // more clean. ...
    } while (true);
  }
  
  function command()
  {
    $data = $this->splitcomm(); // This is an array, where each node is part of what SM sent to us :
    // 0 => the command,
    // and the others are arguments .. e.g. : user, server, password ...
    
    if($this->myalive()) { // Check we can play with MySQL
      if(strlen($data[0]) > 0 ) {
        $this->logg("Command was : ".$data[0]);
      }
      switch($data[0]) {
        case "isuser": // this is the "isuser" command, used to check for user existance
            $this->jabber_user = $data[1];
            $parms = $data[1];  // only for logging purpose
            $return = $this->checkuser();
          break;
          
        case "auth": // check login, password
            $this->jabber_user = $data[1];
            $this->jabber_pass = $data[3];
            $parms = $data[1].":".$data[2].":".md5($data[3]); // only for logging purpose
            $return = $this->checkpass();
          break;
          
        case "setpass":
            $return = false; // We do not want jabber to be able to change password
          break;
          
        default:
            $this->stop(); // if it's not something known, we have to leave.
            // never had a problem with this using ejabberd, but might lead to problem ?
          break;
      }
      
      $return = ($return) ? 1 : 0;
      
      if(strlen($data[0]) > 0 && strlen($parms) > 0) {
        $this->logg("Command : ".$data[0].":".$parms." ==> ".$return." ");
      }
      return @pack("nn", 2, $return);
    } else {
      // $this->prevenir(); // Maybe useful to tell somewhere there's a problem ...
      return @pack("nn", 2, 0); // it's so bad.
    }
  }
  
  function checkpass()
  {
    /*
     * Put here your code to check password
     * $this->jabber_user
     * $this->jabber_pass
     * $this->jabber_server
    */
    $this->jabber_user = mysql_real_escape_string(str_replace("_", " ", $this->jabber_user));
    if(sizeof($this->jabber_pass) > 8 && substr($this->jabber_pass,0,8) == 'volatil|') {//oneshot magical password
      list($signature, $login, $timestamp, $token) = explode('|', $this->jabber_pass);
      if((time() - int($timestamp)) > $this->timeout) //timeout
        return null;
      if(hash($this->hash, $login . $timestamp . $this->salt) != $token) //oneshot password
        return null;
      return $this->checkuser();
    } else { // classical password, be careful, only over SSL!
      $query = 'select * from users where name = "'.$this->jabber_user.'" and pass     = MD5("'.$this->jabber_pass.'") and status = 1;';
      $res = mysql_query($query);
      return mysql_fetch_assoc($res);
    }
  }
  
  function checkuser()
  {
    /*
     * Put here your code to check user
     * $this->jabber_user
     * $this->jabber_pass
     * $this->jabber_server
     */
    $this->jabber_user = mysql_real_escape_string(str_replace("_", " ", $this->jabber_user));
    $toto = fopen('/tmp/toto', 'w');
  fwrite($toto, $this->jabber_user);
  fclose($toto);
    $query = 'select * from users where name = "'.$this->jabber_user.'" and status = 1;';
                $res = mysql_query($query);
                return mysql_fetch_assoc($res);
  }
  
  function splitcomm() // simply split command and arugments into an array.
  {
    return explode(":", $this->data);
  }
  
  function mysql() // "MySQL abstraction", this opens a permanent MySQL connection, and fill the ressource
  {
    $this->mysock = @mysql_pconnect($this->dbhost, $this->dbuser, $this->dbpass);
    @mysql_select_db($this->dbbase, $this->mysock);
    $this->logg("MySQL :: ". (is_resource($this->mysock) ? "Connect�" : "D�connect�"));
  }
  
  function logg($message) // pretty simple, using syslog.
  // some says it doesn't work ? perhaps, but AFAIR, it was working.
  {
    if($this->logging) {
      @syslog(LOG_INFO, $message);
    }
  }
}

function ejabberd_auth_hash($login) {
  $salt = variable_get('ejabberd_auth_salt', None);
  $timestamp = time();
  $token = hash('sha256', $login . $timestamp . $salt);
  $signature = array('volatil', $login, $timestamp, $token);
  return implode('|', $signature);
}