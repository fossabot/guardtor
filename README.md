# GuardTor

GuardTor is a sophisticated PHP library for protecting your application against bad bots, scrappers, anonymous access from tor browsers, strong user input validations, prevent DDOS Attacks and lots more features to come.

## Install:
Use composer to install
```php
composer require mitmelon/guardtor
```

## Usage :

```php
require_once __DIR__."/vendor/autoload.php";

// Place GuardTor Class untop of your application
$guardTor = new GuardTor();
$guardTor->init();
//Your Application Code Here

```
## Properties Setup:

You can change guardtor properties by calling guardtor properties before calling the init() method

```php
//Allow GuardTor to create or modifying .htaccess with added functionalities to prevent bad bots
//Default is false.
//Please make sure you only enable this on development for one request to prevent over-writeups
//Once request is complete from your browser, change $guardTor->createhtaccess = false;
//On production change to $guardTor->createhtaccess = false;
$guardTor->createhtaccess = true;
//Never block tor users
//Default is true.
$guardTor->blocktor = false;
//Set the block page url users will be redirected to once blocked
//Default is __DIR__.'/error.html';
$guardTor->blockLink = 'BLOCK_PAGE_URL';
//Prevent request block once limit is reached
//Default is true;
//Please note that setting this to true requires redis installed.
$guardTor->block_request = false;
//Set request limit per minute to reach before blocking request
//This could be used to prevent DDOS Attacks
//Default is 100 times per minutes
$guardTor->attempt = 100;
```
## Full Documentation :

https://manomitehq.gitbook.io/guardtor/

## Future Updates :

* Spam Detections/Block

# License

Released under the MIT license.