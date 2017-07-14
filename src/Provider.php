<?php
namespace SocialiteProviders\Steein;

use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'STEEIN';

    /**
     * The base Steein URL.
     *
     * @var string
     */
    protected $urlApi = 'https://www.steein.ru';

    /**
     * The API version for the request.
     *
     * @var string
     */
    protected $version = 'v2.0';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['users', 'email'];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://www.steein.ru/oauth/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://www.steein.ru/oauth/token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('https://www.steein.ru/api/'.$this->version.'/users/show', [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['id'],
            'first_name' => array_get($user['name'], 'last_name'),
            'last_name' => array_get($user['name'], 'last_name'),
            'username' => array_get($user, 'username'),
            'avatar' => array_get($user, 'avatar'),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }
        $user = $this->mapUserToObject($this->getUserByToken(
            $token = $this->getAccessTokenResponse($this->getCode())
        ));
        return $user->setToken(array_get($token, 'access_token'));
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessToken($body)
    {
        return json_decode($body, true);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }
}