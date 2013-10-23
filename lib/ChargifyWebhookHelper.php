<?php

/* http://docs.chargify.com/webhooks */

class ChargifyWebhookHelper
{
	public static $log_path = "log/handshake.log";
	
	/*
		Intercept, interpret, and verify the webhook request and return the event and payload

		On success, returns array('event' => 'event name', 'payload' => array('something' => '...'))
	*/
	public static function grabHook($shared_key, $post_array, $raw_post, $server_array)
	{
		//The request signature
		$signature = null;

		//Make sense of the request headers, and tease out the signature
		$headers = self::parseRequestHeaders($server_array);
		if(isset($headers['X-Chargify-Webhook-Signature-Hmac-Sha-256'])) { $signature = $headers['X-Chargify-Webhook-Signature-Hmac-Sha-256']; }
		else { return false; }

		//Set the log file output path
		$log_file = self::$log_path;
		
		//If we have the signature and an event, determine if the package is legit
		if($signature && isset($post_array['event']))
		{
			//If the request checks out, write to the log and return the event type and payload
			if(self::validSignature($signature, $shared_key, $raw_post))
			{
				file_put_contents($log_file, self::genLogOutput($signature, $post_array['event'], true, $raw_post), FILE_APPEND | LOCK_EX);

				return array('event' => $post_array['event'], 'payload' => $post_array['payload']);
			}
		}
		
		file_put_contents($log_file, self::genLogOutput($signature, $post_array['event'], false, $raw_post), FILE_APPEND | LOCK_EX);
		
		return false;
	}

	/*
		Generate the text to write to the log
	*/
	public static function genLogOutput($signature, $event, $success, $raw_post)
	{
		$status = null;
		if($success) { $status = 'SUCCESS'; }
		else { $status = 'FAILED'; }
	
		$log = "[" . date('Y-m-d G:i:s') . "] [Webhook Call - " . $status . "] [event=" . $event . "] [signature=" . $signature 
			. "] " . $raw_post . "\n";
			
		return $log;
	}

	/*
		Tease out the relevant request headers
	*/
	public static function parseRequestHeaders($server_array)
	{
		$headers = array();
		foreach($server_array as $key => $value)
		{
			if(substr($key, 0, 5) <> 'HTTP_') { continue; }
			$header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
			$headers[$header] = $value;
		}
		return $headers;
	}
	
	/*
		A valid signature matches the md5 hashed combination of the shared key and the raw post
	*/
	public static function validSignature($signature, $shared_key, $raw_post)
	{    
		if(hash_hmac('sha256', $raw_post, $shared_key) == $signature) { return true; }
		
		return false;
	}
}