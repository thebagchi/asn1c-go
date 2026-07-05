#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a YEAR-ENCODING CHOICE using APER or UPER from Erlang/OTP compiled
%% modules.
%%
%% Usage:
%%   escript encode_year_encoding.erl -value <int> [-aligned]
%%
%% The script picks the matching CHOICE alternative (immediate, near-future,
%% near-past, remainder) based on the value's range, matching X.691 clause
%% 32.2.3.
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Value, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Choice = choice_for(Value),
    case 'YEAR':encode('YEAR-ENCODING', Choice) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

choice_for(Value) when Value >= 2005, Value =< 2020 ->
    {immediate, Value};
choice_for(Value) when Value >= 2021, Value =< 2276 ->
    {'near-future', Value};
choice_for(Value) when Value >= 1749, Value =< 2004 ->
    {'near-past', Value};
choice_for(Value) ->
    {remainder, Value}.

parse_args(Args) ->
    parse_args(Args, undefined, false).

parse_args([], Value, Aligned) ->
    case Value of
        undefined -> usage("missing -value");
        _ -> {Value, Aligned}
    end;
parse_args(["-value", V | Rest], _, Aligned) ->
    parse_args(Rest, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Value, _) ->
    parse_args(Rest, Value, true);
parse_args([Unknown | _], _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_year_encoding.erl -value <int> [-aligned]~n",
        [Msg]),
    halt(1).
