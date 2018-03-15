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

% Configuration is based on MS demo at https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_sign_in

-define(ENDPOINT, <<"https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_sign_in">>).
-define(KID, "X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk").
-define(OPENID_TARGET_FILE, <<"./src/openid.json">>).
-define(OPENID_KEYS_TARGET_FILE, <<"./src/openid.keys.json">>).

% Get the token and decode it
% Get this token by running the sample at https://github.com/Azure-Samples/active-directory-b2c-dotnetcore-webapi
% You can also do this directly in the B2C Web Portal for a user.
% Paste the JWT Access Token token below as shown in the top textbox on https://jwt.ms
-define(TOKEN, <<"$$$$$dQiLCJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5x2pORnVtMWt2Mll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsifQ.wefwefweffewdHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzc1NTI3ZmYtOWEzNy00MzA3LThiM2QtY2MzMTFmNThkOTI1L3YyLjAvIiwiZXhwIjoxNTIxMTA4NDM2LCJuYmYiOjE1MjExMDQ4MzYsImF1ZCI6IjI1ZWVmNmU0LWM5MDUtNGEwNy04ZWI0LTBkMDhkNWRmOGIzZiIsIm5hbWUiOiJ3ZWJsaXZ6IiwiaWRwIjoidHdpdHRlci5jb20iLCJvaWQiOiIyMTE5ZWEyNy00ZDc4LTQ2MjEtOWIyZC0xYzA5MWQyODI0OTQiLCJzdWIiOiIyMTE5ZWEyNy00ZDc4LTQ2MjEtOWIyZC0xYzA5MWQyODI0OTQiLCJqb2JUaXRsZSI6InRlc3RlciIsImNpdHkiOiJnbGFzZ293Iiwibm9uY2UiOiJkZWZhdWx0Tm9uY2UiLCJzY3AiOiJkZW1vLnJlYWQiLCJhenAiOiI5NTk1YTk5MS1hNzE3LTQ2NjktOWFmMC1kNTg0MjBhZDczM2EiLCJ2ZXIiOiIxLjAiLCJpYXQiOjE1MjExMDQ4MzZ9.Cxwd4MTJu8DjO8hfxPzlEHruPf4OK0rvKEqoHCdJ2Q2hKha0lyf5yc6q7IBBT1_YjrpoaNbUmkcYu0zexMn3gusaT9cCCpKtAr2M-XMIx6n3WJak5zkFToUP5m67OiUDNRTeTjE-Qwvo8yi1DaBcfniCTmkdC-zxDTA3HZtvglqBBUuQWYz9HNkY45Z1pCwCj8EGJLg8t0W5qq9j6ITS9HndYUtiwAY-NQfq_OWq14mWAT9h6vlbv9eu4Ep2elv8zgZq64-lYzY4loEQANiC8rLZukNf9cSsdsgM7Hj5bHqTYfeOuVpx1M_iE2fmYcYf0pQMAXtWXhrQp5NV-FTJ-Q">>).

downloadOpenId() ->
  Response  = httpc:request(?ENDPOINT),
    case Response of
      {ok, {{_, 200, "OK"}, _Headers, Body}} ->
         file:write_file(?OPENID_TARGET_FILE, Body);
      _ ->
        io:format("Error~n")
     end.

downloadOpenIdKeys(Uri) ->
   Response  = httpc:request(binary_to_list(Uri)),
   case Response of
     {ok, {{_, 200, "OK"}, _Headers, Body}} ->
        file:write_file(?OPENID_KEYS_TARGET_FILE, Body);
     _ ->
       io:format("Error~n")
    end.

getJwksUri() ->
  {ok, Json} = file:read_file(?OPENID_TARGET_FILE),
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
   {ok, Json} = file:read_file(?OPENID_KEYS_TARGET_FILE),

   % get a list of all the keys in the document
   #{<<"keys">> := JWTs} = jsx:decode(Json, [return_maps]),

   % enumerate each of the keys
   lists:foreach(
        fun(X) ->
	     Kid = maps:get(<<"kid">>, X),
	     {ok, RSAPubKey} = jwk:decode(Kid, Json),
	     PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', RSAPubKey),
	     PemBin = public_key:pem_encode([PemEntry]),
	     File = string:concat("./src/", binary_to_list(Kid)),
	     File1 = string:concat(File, ".key"),
	     file:write_file(File1, PemBin)
        end,
        JWTs
   ),


    % at this point we validate the token you obtained from the web api sample
    TestName = ?KID,
    TestFile = string:concat("./src/", TestName),
    TestFile1 = string:concat(TestFile, ".key"),
    {ok, TestKey} = file:read_file(TestFile1),
    [ RSAEntry ] = public_key:pem_decode(TestKey),
    KeyDecoded = public_key:pem_entry_decode(RSAEntry),


RT = jwt:decode(?TOKEN, KeyDecoded),
    case jwt:decode(?TOKEN, KeyDecoded) of
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
