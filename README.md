[![Build status](https://ci.appveyor.com/api/projects/status/0dmw9ob2l5bd9ck2?svg=true)](https://ci.appveyor.com/project/tgardner/samlidp-owin)
SamlIdp.Owin
=============

An Owin middleware to create a SAML IdP, based on the [Kentor.AuthServices](https://github.com/KentorIT/authservices)

## Installation
```
Install-Package SamlIdp.Owin
```

## Endpoints
* `/metadata` - SAML metadata
* `/logout` - SSO logout
* `/authorize` - SAML authentication requests
* `/artifact` - SAML artifact resolution

## Example
```
app.Map("/saml", saml =>
{
    saml.UseCookieAuthentication(new CookieAuthenticationOptions
    {
        AuthenticationType = "Cookies"
    });

    saml.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
    {
        Authority = "https://www.example.com",
        ClientId = "example",
        ClientSecret = "example123",
        RedirectUri = "http://www.example.com/saml",
        ResponseType = "code id_token token",
        Scope = "openid",
        SignInAsAuthenticationType = "Cookies"
    });

    var options = new SamlIdpOptions
    {
        AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
        SigningCertificate = Certificate.Get()
    };
    saml.UseSamlIdp(options);
});
```
