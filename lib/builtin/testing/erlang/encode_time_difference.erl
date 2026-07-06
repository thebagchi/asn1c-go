#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a TIME-DIFFERENCE SEQUENCE using APER or UPER from Erlang/OTP
%% compiled modules.
%%
%% Usage:
%%   escript encode_time_difference.erl -sign <positive|negative> -hours <int> [-minutes <int>] [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Sign, Hours, Minutes, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    MinutesVal = case Minutes of undefined -> asn1_NOVALUE; _ -> Minutes end,
    Value = {'TIME-DIFFERENCE', Sign, Hours, MinutesVal},
    case 'TIME-DIFFERENCE':encode('TIME-DIFFERENCE', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

parse_args(Args) ->
    parse_args(Args, undefined, undefined, undefined, false).

parse_args([], Sign, Hours, Minutes, Aligned) ->
    case {Sign, Hours} of
        {undefined, _} -> usage("missing -sign");
        {_, undefined} -> usage("missing -hours");
        _ -> {Sign, Hours, Minutes, Aligned}
    end;
parse_args(["-sign", V | Rest], _, Hours, Minutes, Aligned) ->
    parse_args(Rest, list_to_atom(V), Hours, Minutes, Aligned);
parse_args(["-hours", V | Rest], Sign, _, Minutes, Aligned) ->
    parse_args(Rest, Sign, list_to_integer(V), Minutes, Aligned);
parse_args(["-minutes", V | Rest], Sign, Hours, _, Aligned) ->
    parse_args(Rest, Sign, Hours, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Sign, Hours, Minutes, _) ->
    parse_args(Rest, Sign, Hours, Minutes, true);
parse_args([Unknown | _], _, _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_time_difference.erl -sign <positive|negative> -hours <int> [-minutes <int>] [-aligned]~n",
        [Msg]),
    halt(1).
