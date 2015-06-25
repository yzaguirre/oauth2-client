<?php

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Entity\User;
use League\OAuth2\Client\Token\AccessToken;

class OpenAM extends AbstractProvider
{
    public $scopeSeparator = ' ';

    public $scopes = [
        'givenname',
        'inetuserstatus',
        'sn',
        'mail',
        'cn'
    ];
    public $responseType = 'json';

    public $domain = 'https://openam.server.com';

    public function urlAuthorize()
    {
        return $this->domain.'/oauth2/authorize';
    }

    public function urlAccessToken()
    {
        return $this->domain.'/oauth2/access_token';
    }

    public function urlUserDetails(AccessToken $token)
    {
        return $this->domain.'/oauth2/tokeninfo?access_token='.$token;
    }

    public function userDetails($response, AccessToken $token)
    {
        $user = new User();

        $name = (isset($response->cn)) ? $response->cn : null;
        $email = (isset($response->mail)) ? $response->mail : null;

        $user->exchangeArray([
            'uid' => $response->id,
            'nickname' => $response->givenname, // change for other scope param
            'firstname' => $response->givenname,
            'lastname'=> $response->sn,
            'name' => $name,
            'email' => $email
        ]);

        return $user;
    }

    public function userUid($response, AccessToken $token)
    {
        return $response->id;
    }

    public function getUserEmails(AccessToken $token)
    {
        $response = $this->fetchUserEmails($token);

        return $this->userEmails(json_decode($response), $token);
    }

    public function userEmail($response, AccessToken $token)
    {
        return isset($response->mail) && $response->mail ? $response->mail : null;
    }

    public function userEmails($response, AccessToken $token)
    {
        return $response;
    }

    public function userScreenName($response, AccessToken $token)
    {
        return $response->cn;
    }

    protected function fetchUserEmails(AccessToken $token)
    {
        $url = $this->urlUserEmails($token);

        $headers = $this->getHeaders($token);

        return $this->fetchProviderData($url, $headers);
    }
    /**
     * Prepare the access token response for the grant. Custom mapping of
     * expirations, etc should be done here.
     *
     * @param  array $result
     * @return array
     */
    protected function prepareAccessTokenResult(array $result)
    {
        $this->setResultUid($result);
        return $result;
    }
}
