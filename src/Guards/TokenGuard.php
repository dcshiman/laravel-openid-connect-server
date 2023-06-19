<?php

namespace Idaas\Passport\Guards;

use Illuminate\Http\Request;
use Laravel\Passport\Guards\TokenGuard as GuardsTokenGuard;

class TokenGuard extends GuardsTokenGuard
{

    public function user()
    {
        /**
         * Support for https://tools.ietf.org/id/draft-ietf-oauth-v2-bearer-00.html#body-param
         */
        if (($access_token = $this->request->input('access_token')) != null && $this->request->getContentTypeFormat() == 'application/x-www-form-urlencoded') {
            $this->request->headers->set('Authorization', 'Bearer ' . $access_token);
        }

        return parent::user();
    }
}
