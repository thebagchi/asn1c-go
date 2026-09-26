#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a MINUTES-ENCODING SEQUENCE using APER or UPER from Erlang/OTP
%% compiled modules.
%%
%% Usage:
%%   escript encode_minutes_encoding.erl -hours <int> -minutes <int> [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Hours, Minutes, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Value = {'MINUTES-ENCODING', Hours, Minutes},
    case 'TIME-DIFFERENCE':encode('MINUTES-ENCODING', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

parse_args(Args) ->
    parse_args(Args, undefined, undefined, false).

parse_args([], Hours, Minutes, Aligned) ->
    case {Hours, Minutes} of
        {undefined, _} -> usage("missing -hours");
        {_, undefined} -> usage("missing -minutes");
        _ -> {Hours, Minutes, Aligned}
    end;
parse_args(["-hours", V | Rest], _, Minutes, Aligned) ->
    parse_args(Rest, list_to_integer(V), Minutes, Aligned);
parse_args(["-minutes", V | Rest], Hours, _, Aligned) ->
    parse_args(Rest, Hours, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Hours, Minutes, _) ->
    parse_args(Rest, Hours, Minutes, true);
parse_args([Unknown | _], _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_minutes_encoding.erl -hours <int> -minutes <int> [-aligned]~n",
        [Msg]),
    halt(1).
