azure_ad_b2c_claims
===================

This sample demonstates validating and retrieving claims from an Azure AD B2C directory instance.

## Configure Azure and get An Azure Token

You can run the sample .Net Core app to get a Token or do this directly in the Azure Portal.

Follow the instructions at [An ASP.NET Core 2.0 web API with Azure AD B2C](https://github.com/Azure-Samples/active-directory-b2c-dotnetcore-webapi) to configure Azure B2C and get an Azure Access Token


## Configure the Erlang Application


```bash
$ git clone https://github.com/ParamountVentures/azure-ad-b2c-claims-erlang
```

Edit the src/azure_ad_b2c_claims.app.src and change the following constants from your B2C instance:

```erlang
    {tenant, "fabrikamb2c"},
    {policy, "B2C_1_sign_in"},
    {folder, "./src/"},
    {testtoken, <<"123.456.789">>}
```

Now run the application:

```bash
    $ rebar3 shell
    $ application:start(azure_ad_b2c_claims).
```

Output:

You will see the output value of the "name" claim as stored in B2C for the given user:

{ok,<<"somename">>}
