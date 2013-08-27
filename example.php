<?php

include "lib/ChargifyWebhookHelper.php";

$shared_key = "set_inside_chargify"; //http://docs.chargify.com/webhooks#finding-your-site-shared-key
$post_array = $_POST;
$raw_post = file_get_contents("php://input");
$server_array = $_SERVER;

//returns array('event' => string, 'payload' => array)
$request = ChargifyWebhookHelper::grabHook($shared_key, $post_array, $raw_post, $server_array);
