<?php
use GuardTor\GuardTor;
require_once __DIR__.'/vendor/autoload.php';

$guard = new GuardTor();
$guard->createhtaccess = false;

var_dump($guard);