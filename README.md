# Steein OAuth2 Provider for Laravel Socialite


## Installation

### 0. Credentials

Obtain your app ID and secret from [steein.ru](https://www.steein.ru/developers/docs). You must set up a valid name and callback URL.

### 1. Composer
This assumes that you have composer installed globally:

composer require steeinpassport/steein-laravel-oauth


## 2. Service Provider

Remove ```Laravel\Socialite\SocialiteServiceProvider``` from your ```providers[]``` array in ***config\app.php*** if you have added it already.
Add ```\SocialiteProviders\Manager\ServiceProvider::class``` to your ```providers[]``` array in ***config\app.php***.
For example:

```php
'providers' => [
    // a whole bunch of providers
    // remove 'Laravel\Socialite\SocialiteServiceProvider',
    \SocialiteProviders\Manager\ServiceProvider::class, // add
];
```


## 3. Add the Event and Listeners

Add SocialiteProviders\Manager\SocialiteWasCalled event to your listen[] array in <app_name>/Providers/EventServiceProvider.
Add your listeners (i.e. the ones from the providers) to the SocialiteProviders\Manager\SocialiteWasCalled[] that you just created.
The listener that you add for this provider is 'SocialiteProviders\Telegram\TelegramExtendSocialite@handle',.
Note: You do not need to add anything for the built-in socialite providers unless you override them with your own providers.

For example:

```php
/**
 * The event handler mappings for the application.
 *
 * @var array
 */
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // add your listeners (aka providers) here
        'SocialiteProviders\Steein\SteeinExtendSocialite@handle',
    ],
];
```

## 4. Environment Variables

If you add environment values to your ```.env``` as exactly shown below, ***you do not need to add an entry to the services array.***

### Append provider values to your ```.env``` file

```
// other values above
STEEIN_KEY=yourkeyfortheservice
STEEIN_SECRET=yoursecretfortheservice
STEEIN_REDIRECT_URI=https://example.com/login/callback
```

### Add to ```config/services.php```.

You do not need to add this if you add the values to the .env exactly as shown above. The values below are provided as a convenience in the case that a developer is not able to use the .env method

```
'steein' => [
    'client_id' => env('STEEIN_KEY'),
    'client_secret' => env('STEEIN_SECRET'),
    'redirect' => env('STEEIN_REDIRECT_URI'),  
]
```

## Usage

You should now be able to use it like you would regularly use Socialite (assuming you have the facade installed):

```php
    return Socialite::with('steein')->redirect();
```


### Lumen Support

You can use Socialite providers with Lumen. Just make sure that you have facade support turned on and that you follow the setup directions properly.

***Note:*** If you are using this with Lumen, all providers will automatically be stateless since Lumen does not keep track of state.

Also, configs cannot be parsed from the ```services[]``` in Lumen. You can only set the values in the ```.env``` file as shown exactly in this document. If needed, you can also override a config (shown below).

Stateless

You can set whether or not you want to use the provider as stateless. Remember that the OAuth provider (Twitter, Tumblr, etc) must support whatever option you choose.

***Note:*** If you are using this with Lumen, all providers will automatically be stateless since Lumen does not keep track of state.

```php
// to turn off stateless
return Socialite::with('steein')->stateless(false)->redirect();

// to use stateless
return Socialite::with('steein')->stateless()->redirect();
```