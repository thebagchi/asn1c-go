#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode an ANY-YEAR-WEEK-ENCODING SEQUENCE using APER or UPER from
%% Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_any_year_week_encoding.erl -year <int> -week <int> [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Year, Week, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Value = {'ANY-YEAR-WEEK-ENCODING', Year, Week},
    case 'YEAR':encode('ANY-YEAR-WEEK-ENCODING', Value) of
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

parse_args([], Year, Week, Aligned) ->
    case {Year, Week} of
        {undefined, _} -> usage("missing -year");
        {_, undefined} -> usage("missing -week");
        _ -> {Year, Week, Aligned}
    end;
parse_args(["-year", V | Rest], _, Week, Aligned) ->
    parse_args(Rest, list_to_integer(V), Week, Aligned);
parse_args(["-week", V | Rest], Year, _, Aligned) ->
    parse_args(Rest, Year, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Year, Week, _) ->
    parse_args(Rest, Year, Week, true);
parse_args([Unknown | _], _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_any_year_week_encoding.erl -year <int> -week <int> [-aligned]~n",
        [Msg]),
    halt(1).
