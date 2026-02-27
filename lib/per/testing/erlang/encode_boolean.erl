#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a BOOLEAN value using APER or UPER from Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_boolean.erl -value <true|false> [-aligned]
%%
%% Flags:
%%   -value <true|false>  boolean value to encode
%%   -aligned             use APER (aligned PER); omit for UPER (default)
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Value, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    case 'BOOLEANS':encode('BOOL', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

parse_args(Args) ->
    parse_args(Args, undefined, false).

parse_args([], Value, Aligned) ->
    case Value of
        undefined -> usage("missing -value");
        _ -> {Value, Aligned}
    end;
parse_args(["-value", "true" | Rest], _, Aligned) ->
    parse_args(Rest, true, Aligned);
parse_args(["-value", "false" | Rest], _, Aligned) ->
    parse_args(Rest, false, Aligned);
parse_args(["-aligned" | Rest], Value, _) ->
    parse_args(Rest, Value, true);
parse_args([Unknown | _], _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_boolean.erl -value <true|false> [-aligned]~n",
        [Msg]),
    halt(1).
