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

-export([start/1,
         stop/1,
         compare_encoded_and_plain_password/2,
         mongo_user_exists/1,
         mongo_check_password/2]).

% functions used by ejabberd_auth
-export([login/2,
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
    ?INFO_MSG("Module: ~p starting...", [?MODULE]),
    mongodb:replicaSets(xmpp_mongo, ["localhost:27017"]),
    mongodb:connect(xmpp_mongo),
    ok.

stop(Host) ->
    ?INFO_MSG("Module: ~p stoping...", [?MODULE]),
    mongodb:deleteConnection(xmpp_mongo),
    ok.


%%%
%%% Authentication callbacks
%%%

plain_password_required() -> 
    true.

check_password(User, _Server, Password) ->
    Password_parsed = lists:nth(2, string:tokens(Password, "#")),
    mongo_check_password(User, Password_parsed).

check_password(User, Server, Password, _Digest, _DigestGen) ->
    ?INFO_MSG("User: ~p, Server: ~p, Password: ~p, Digest: ~p, DigestGen: ~p~n", [User, Server, Password, _Digest, _DigestGen]),
    check_password(User, Server, Password).

is_user_exists(User, _Server) ->
    ?INFO_MSG("is_user_exists: [args]: ~p, ~p ~n", [User, _Server]),
    mongo_user_exists(User).

set_password(_User, _Server, _Password) ->
    {error, not_allowed}.

try_register(_,_,_) -> 
    {error, not_allowed}.

dirty_get_registered_users() ->
    [].

get_vh_registered_users(_) -> 
    [].

get_password(User, Server) ->
    get_password_s(User, Server).

get_password_s(User, Server) ->
    "ABCGULU".

remove_user(_,_) ->
    {error, not_allowed}.

remove_user(_,_,_) ->
    {error, not_allowed}.

login(User, Server) ->
    ?INFO_MSG("django_mongodb_djangouser: fuck~n", []),
    true.

%%%
%%% Custom functions
%%%

compare_encoded_and_plain_password(Encoded_P, Plain_P) ->
    Encoded_P_Tokens = string:tokens(Encoded_P, "$"),
    P_salt = lists:nth(2, Encoded_P_Tokens),
    P_encoded = lists:nth(3, Encoded_P_Tokens),
    Encoded_P_from_plain = string:to_lower(sha1:hexstring(P_salt ++ Plain_P)),
    Encoded_P_from_plain == P_encoded.

generate_xmpp_internal_key(

    
%%% TODO: mongo_user_exists()

mongo_user_exists(User) ->
    ?INFO_MSG("mongo_user_exists ~n", []),
    Conn = mongoapi:new(xmpp_mongo, <<"gulu">>),
    {ok, Data} = Conn:find(<<"auth_user">>, [{<<"username">>, User}], undefined, 0, 1),
    case length(Data) of
        0 -> false;
        1 -> true
    end.


mongo_check_password(User, Password) -> 
    %%% Notice: Password appeared here is refered to xmpp_internal_key in user_profile module.
    ?INFO_MSG("mongo_check_password: [User]~p [Password]~p ~n", [User, Password]),
    Conn = mongoapi:new(xmpp_mongo, <<"gulu">>),
    {ok, Data_authuser_list} = Conn:find(<<"auth_user">>, [{<<"username">>, User}], undefined, 0, 1),
    Data_authuser = lists:nth(1, Data_authuser_list),
    Data_authuser_oid = proplists:get_value(<<"_id">>, Data_authuser),
    {ok, Data_userprofile_list} = Conn:find(<<"user_profiles_userprofile">>, [{<<"user_id">>, Data_authuser_oid}], undefined, 0, 1),
    Data_userprofile = lists:nth(1, Data_userprofile_list),
    Data_userprofile_password = proplists:get_value(<<"xmpp_internal_key">>, Data_userprofile),
    Data_userprofile_password == Password.
