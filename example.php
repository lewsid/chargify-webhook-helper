<?php

include "lib/ChargifyWebhookHelper.php";

$shared_key = "VwubnkmwIth4FGkRfu";
$post_array = $_POST;
$raw_post = file_get_contents("php://input");
$server_array = $_SERVER;

$request = ChargifyWebhookHelper::grabHook($shared_key, $post_array, $raw_post, $server_array);

echo '<pre>'; print_r($request); die();