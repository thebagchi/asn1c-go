#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a YEAR-MONTH-ENCODING SEQUENCE using APER or UPER from Erlang/OTP
%% compiled modules.
%%
%% Usage:
%%   escript encode_year_month_encoding.erl -year <int> -month <int> [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Year, Month, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Value = {'YEAR-MONTH-ENCODING', choice_for(Year), Month},
    case 'YEAR':encode('YEAR-MONTH-ENCODING', Value) of
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
    parse_args(Args, undefined, undefined, false).

parse_args([], Year, Month, Aligned) ->
    case {Year, Month} of
        {undefined, _} -> usage("missing -year");
        {_, undefined} -> usage("missing -month");
        _ -> {Year, Month, Aligned}
    end;
parse_args(["-year", V | Rest], _, Month, Aligned) ->
    parse_args(Rest, list_to_integer(V), Month, Aligned);
parse_args(["-month", V | Rest], Year, _, Aligned) ->
    parse_args(Rest, Year, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Year, Month, _) ->
    parse_args(Rest, Year, Month, true);
parse_args([Unknown | _], _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_year_month_encoding.erl -year <int> -month <int> [-aligned]~n",
        [Msg]),
    halt(1).
