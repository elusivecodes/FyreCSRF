# FyreCSRF

**FyreCSRF** is a free, open-source CSRF protection library for *PHP*.


## Table Of Contents
- [Installation](#installation)
- [Methods](#methods)
- [Middleware](#middleware)



## Installation

**Using Composer**

```
composer require fyre/csrf
```

In PHP:

```php
use Fyre\Security\CsrfProtection;
```


## Methods

**Check Token**

Check CSRF token.

- `$request` is the [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests).

```php
CrsfProtection::checkToken($request);
```

**Disable**

Disable the CSRF protection.

```php
CsrfProtection::disable();
```

**Enable**

Enable the CSRF protection.

```php
CsrfProtection::enable();
```

**Get Field**

Get the CSRF token field name.

```php
$field = CsrfProtection::getField();
```

**Get Header**

Get the CSRF token header name.

```php
$header = CsrfProtection::getHeader();
```

**Get Key**

Get the CSRF session key.

```php
$key = CsrfProtection::getKey();
```

**Get Token**

Get the CSRF token.

```php
$token = CsrfProtection::getToken();
```

**Get Token Hash**

Get the CSRF token hash.

```php
$tokenHash = CsrfProtection::getTokenHash();
```

**Is Enabled**

Determine if the CSRF protection is enabled.

```php
$enabled = CsrfProtection::isEnabled();
```

**Set Field**

Set the CSRF token field name.

- `$field` is a string representing the CSRF token field name.

```php
CsrfProtection::setField($field);
```

**Set Header**

Set the CSRF token header name.

- `$header` is a string representing the CSRF token header name.

```php
CsrfProtection::setHeader($header);
```

**Set Key**

Set the CSRF session key.

- `$key` is a string representing the CSRF session key.

```php
CsrfProtection::setKey($key);
```

**Skip Check Callback**

Set the skip check callback.

- `$skipCheck` is a *Closure* that accepts a [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests) as the first argument.

```php
CsrfProtection::skipCheckCallback($skipCheck);
```

The skip check callback should return *true* if the CSRF check should not be performed.


## Middleware

```php
use Fyre\Security\Middleware\CsrfProtectionMiddleware;
```

- `$options` is an array containing options for the middleware.
    - `field` is a string representing the CSRF token field name, and will default to "*csrf_token*".
    - `header` is a string representing the CSRF token header name, and will default to "*Csrf-Token*".
    - `key` is a string representing the CSRF session key and will default to "*_csrfToken*".
    - `skipCheck` is a *Closure* that accepts a [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests) as the first argument.

```php
$middleware = new CsrfProtectionMiddleware($options);
```

The skip check callback should return *true* if the CSRF check should not be performed.

**Process**

- `$request` is a [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests).
- `$handler` is a [*RequestHandler*](https://github.com/elusivecodes/FyreMiddleware#request-handlers).

```php
$response = $middleware->process($request, $handler);
```

This method will return a [*ClientResponse*](https://github.com/elusivecodes/FyreServer#client-responses).