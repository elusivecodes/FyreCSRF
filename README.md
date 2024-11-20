# FyreCSRF

**FyreCSRF** is a free, open-source CSRF protection library for *PHP*.


## Table Of Contents
- [Installation](#installation)
- [Basic Usage](#basic-usage)
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


## Basic Usage

- `$container` is a [*Container*](https://github.com/elusivecodes/FyreContainer).
- `$config` is a [*Config*](https://github.com/elusivecodes/FyreConfig).

```php
$csrfProtection = new CsrfProtection($container, $config);
```

Default configuration options will be resolved from the "*Csrf*" key in the [*Config*](https://github.com/elusivecodes/FyreConfig).

- `$options` is an array containing the configuration options.
    - `cookie` is an array containing CSRF cookie options.
        - `name` is a string representing the cookie name, and will default to "*CsrfToken*".
        - `expires` is a number representing the cookie lifetime, and will default to *0*.
        - `domain` is a string representing the cookie domain, and will default to "".
        - `path` is a string representing the cookie path, and will default to "*/*".
        - `secure` is a boolean indicating whether to set a secure cookie, and will default to *true*.
        - `httpOnly` is a boolean indicating whether to the cookie should be HTTP only, and will default to *false*.
        - `sameSite` is a string representing the cookie same site, and will default to "*Lax*".
    - `salt` is a string representing the CSRF session key and will default to "*_csrfToken*".
    - `field` is a string representing the CSRF token field name, and will default to "*csrf_token*".
    - `header` is a string representing the CSRF token header name, and will default to "*Csrf-Token*".
    - `skipCheck` is a *Closure* that accepts a [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests) as the first argument.

```php
$container->use(Config::class)->set('Csrf', $options);
```

**Autoloading**

It is recommended to bind the *CsrfProtection* to the [*Container*](https://github.com/elusivecodes/FyreContainer) as a singleton.

```php
$container->singleton(CsrfProtection::class);
```

Any dependencies will be injected automatically when loading from the [*Container*](https://github.com/elusivecodes/FyreContainer).

```php
$csrfProtection = $container->use(CsrfProtection::class);
```


## Methods

**Before Response**

Update the [*ClientResponse*](https://github.com/elusivecodes/FyreServer#client-responses) before sending to client.

```php
$response = $csrfProtection->beforeResponse($request, $response);
```

**Check Token**

Check CSRF token.

- `$request` is the [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests).

```php
$csrfProtection->checkToken($request);
```

**Get Cookie Token**

Get the CSRF cookie token.

```php
$cookieToken = $csrfProtection->getCookieToken();
```

**Get Field**

Get the CSRF token field name.

```php
$field = $csrfProtection->getField();
```

**Get Form Token**

Get the CSRF form token.

```php
$formToken = $csrfProtection->getFormToken();
```

**Get Header**

Get the CSRF token header name.

```php
$header = $csrfProtection->getHeader();
```


## Middleware

```php
use Fyre\Security\Middleware\CsrfProtectionMiddleware;
```

- `$csrfProtection` is a *CsrfProtection*.

```php
$middleware = new CsrfProtectionMiddleware($csrfProtection);
```

Any dependencies will be injected automatically when loading from the [*Container*](https://github.com/elusivecodes/FyreContainer).

```php
$middleware = $container->build(CsrfProtectionMiddleware::class);
```

**Handle**

Handle a [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests).

- `$request` is a [*ServerRequest*](https://github.com/elusivecodes/FyreServer#server-requests).
- `$next` is a *Closure*.

```php
$response = $middleware->handle($request, $next);
```

This method will return a [*ClientResponse*](https://github.com/elusivecodes/FyreServer#client-responses).