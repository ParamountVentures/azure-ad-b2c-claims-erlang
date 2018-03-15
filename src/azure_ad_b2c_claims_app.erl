%%%-------------------------------------------------------------------
%% @doc azure_ad_b2c_claims public API
%% @end
%%%-------------------------------------------------------------------

-module(azure_ad_b2c_claims_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

-define(OPENID_TARGET_FILE, "openid.json").
-define(OPENID_KEYS_TARGET_FILE, "openid.keys.json").

downloadOpenId() ->
  {_, Tenant} = application:get_env(azure_ad_b2c_claims, tenant),
  {_, Policy} = application:get_env(azure_ad_b2c_claims, policy),

  % build the endpoint
  EndpointTenant = string:concat("https://login.microsoftonline.com/", Tenant),
  EndpointUri = string:concat(EndpointTenant, ".onmicrosoft.com/v2.0/.well-known/openid-configuration?p="),
  EndpointPolicyUri = string:concat(EndpointUri, Policy),

  Response  = httpc:request(EndpointPolicyUri),
    case Response of
      {ok, {{_, 200, "OK"}, _Headers, Body}} ->
	 {_, Folder} = application:get_env(azure_ad_b2c_claims, folder),
	 Location = string:concat(Folder, ?OPENID_TARGET_FILE),
         file:write_file(Location, Body);
      _ ->
        io:format("Error~n")
     end.

downloadOpenIdKeys(Uri) ->
   Response  = httpc:request(binary_to_list(Uri)),
   case Response of
     {ok, {{_, 200, "OK"}, _Headers, Body}} ->
        {_, Folder} = application:get_env(azure_ad_b2c_claims, folder),
        Location = string:concat(Folder, ?OPENID_KEYS_TARGET_FILE),
        file:write_file(Location, Body);
     _ ->
       io:format("Error~n")
    end.

getJwksUri() ->
  {_, Folder} = application:get_env(azure_ad_b2c_claims, folder),
  Location = string:concat(Folder, ?OPENID_TARGET_FILE),
  {ok, Json} = file:read_file(Location),
  JsonParsed = jsx:decode(Json, [return_maps]),
  Uri = maps:get(<<"jwks_uri">>, JsonParsed),
  {ok, Uri}.

start(_StartType, _StartArgs) ->
    application:ensure_all_started(jwt),

    % get the open id config document locally
    downloadOpenId(),

    % get the jwks uri from the config document
    {ok, Uri} = getJwksUri(),

   % get the doc containing the keys
   downloadOpenIdKeys(Uri),

   % now decode each of the keys as a binary pem to use later
   {_, Folder} = application:get_env(azure_ad_b2c_claims, folder),
   Location = string:concat(Folder, ?OPENID_KEYS_TARGET_FILE),
   {ok, Json} = file:read_file(Location),

   % get a list of all the keys in the document
   #{<<"keys">> := JWTs} = jsx:decode(Json, [return_maps]),

   % enumerate each of the keys
   lists:foreach(
        fun(X) ->
	     Kid = maps:get(<<"kid">>, X),
	     {ok, RSAPubKey} = jwk:decode(Kid, Json),
	     PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', RSAPubKey),
	     PemBin = public_key:pem_encode([PemEntry]),
             File = string:concat(Folder, binary_to_list(Kid)),
%	     File = string:concat("./src/", binary_to_list(Kid)),
	     File1 = string:concat(File, ".pem"),
	     file:write_file(File1, PemBin)
        end,
        JWTs
   ),


    % at this point we validate the token you obtained from the web api sample
    {_, TestName} = application:get_env(azure_ad_b2c_claims, kid),
    TestFile = string:concat(Folder, TestName),
%    TestFile = string:concat("./src/", TestName),
    TestFile1 = string:concat(TestFile, ".pem"),
    {ok, TestKey} = file:read_file(TestFile1),
    [ RSAEntry ] = public_key:pem_decode(TestKey),
    KeyDecoded = public_key:pem_entry_decode(RSAEntry),

    {_, Token} = application:get_env(azure_ad_b2c_claims, testtoken),
    case jwt:decode(Token, KeyDecoded) of
	{error,invalid_token} ->
	    {error,invalid_token};
  	{ok, Claims} ->
	    erlang:display(maps:find(<<"name">>, Claims));
	_ ->
	    {error,invalid_token}
    end,

    azure_ad_b2c_claims_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
