#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode an HOURS-ENCODING INTEGER using APER or UPER from Erlang/OTP
%% compiled modules.
%%
%% Usage:
%%   escript encode_hours_encoding.erl -hours <int> [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Hours, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    case 'TIME-DIFFERENCE':encode('HOURS-ENCODING', Hours) of
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

parse_args([], Hours, Aligned) ->
    case Hours of
        undefined -> usage("missing -hours");
        _ -> {Hours, Aligned}
    end;
parse_args(["-hours", V | Rest], _, Aligned) ->
    parse_args(Rest, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Hours, _) ->
    parse_args(Rest, Hours, true);
parse_args([Unknown | _], _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_hours_encoding.erl -hours <int> [-aligned]~n",
        [Msg]),
    halt(1).
