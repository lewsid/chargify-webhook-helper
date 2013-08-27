<?php

include "lib/ChargifyWebhookHelper.php";

$shared_key = "set_inside_chargify"; //http://docs.chargify.com/webhooks#finding-your-site-shared-key
$post_array = $_POST;
$raw_post = file_get_contents("php://input");
$server_array = $_SERVER;

//returns array('event' => string, 'payload' => array)
$request = ChargifyWebhookHelper::grabHook($shared_key, $post_array, $raw_post, $server_array);

switch($_POST['event'])
{
    case 'renewal_failure':
      //Handle account renewal failure, set flag on user account that should redirect them to form
      $acoount_id = $_POST['payload']['subscription']['customer']['reference'];
      break;
      
    case 'renewal_success:':
      //etc...
}
