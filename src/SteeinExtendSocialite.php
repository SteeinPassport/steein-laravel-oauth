<?php

namespace SocialiteProviders\Steein;

use SocialiteProviders\Manager\SocialiteWasCalled;

class SteeinExtendSocialite
{
    /**
     * Execute the provider.
     * @param SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('steein', __NAMESPACE__.'\Provider');
    }
}