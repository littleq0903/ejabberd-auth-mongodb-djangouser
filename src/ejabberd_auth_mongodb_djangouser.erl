%%%----------------------------------------------------------------------------------------------------
%%% File    : ejabberd_auth_mongodb_djangouser.erl
%%% Author  : Colin Su <littleq0903@gmail.com>
%%% Purpose : Authentification via MongoDB for Django user mechanism
%%% Created :
%%%----------------------------------------------------------------------------------------------------


-module(ejabberd_auth_mongodb_djangouser).
-author('littleq0903@gmail.com').

%% Import SHA1 module
-import(sha1, [hexstring/1]).
%% External exports
-export([start/1,
         stop/1,
         set_password/3,
         check_password/3,
         check_password/5,
         try_register/3,
         dirty_get_registered_users/0,
         get_vh_registered_users/1,
         get_password/2,
         get_password_s/2,
         is_user_exists/2,
         remove_user/2,
         remove_user/3,
         plain_password_required/0
        ]).

-include("ejabberd.hrl").


%%% 
%%% Server behavior callbacks
%%%

start(Host) ->
    ok.

stop(Host) ->
    ok.

%%%
%%% Authentication callbacks
%%%

plain_password_required() -> 
    true.

check_password(User, _Server, Password) ->
    mongo_check_password(User, Password).

check_password(User, Server, Password, _Digest, _DigestGen) ->
    check_password(User, Server, Password).

is_user_exists(User, _Server) ->
    mongo_user_exists(User).

set_password(_User, _Server, _Password) ->
    {error, not_allowed}.

try_register(_,_,_) -> 
    {error, not_allowed}.

dirty_get_registered_users() ->
    [].

get_vh_registered_users(_) -> 
    [].

get_password(_,_) ->
    false.

get_password_s(_,_) ->
    "".

remove_user(_,_) ->
    {error, not_allowed}.

remove_user(_,_,_) ->
    {error, not_allowed}.

%%%
%%% Custom functions
%%%

compare_encoded_and_plain_password(Encoded_P, Plain_P) ->
    Encoded_P_Tokens = string:tokens(Encoded_P, "$"),
    P_salt = lists:nth(2, Encoded_P_Tokens),
    P_encoded = lists:nth(3, Encoded_P_Tokens),
    Encoded_P_from_plain = string:to_lower(sha1:hexstring(P_salt ++ Encoded_P)),
    Encoded_P_from_plain == P_encoded.

    
%%% TODO: mongo_user_exists()

mongo_user_exists(User) ->
    true.

mongo_check_password(User, Password) -> 
    true.
