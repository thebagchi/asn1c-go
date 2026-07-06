#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING SEQUENCE using APER
%% or UPER from Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_time_of_day_and_diff_and_fraction_encoding.erl -hours <int> -minutes <int> -seconds <int> -fraction <int> -sign <positive|negative> -diff-hours <int> [-diff-minutes <int>] [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Hours, Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    DiffMinutesVal = case DiffMinutes of undefined -> asn1_NOVALUE; _ -> DiffMinutes end,
    LocalTime = {'TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING_local-time', Hours, Minutes, Seconds, Fraction},
    TimeDifference = {'TIME-DIFFERENCE', Sign, DiffHours, DiffMinutesVal},
    Value = {'TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING', LocalTime, TimeDifference},
    case 'TIME-DIFFERENCE':encode('TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

parse_args(Args) ->
    parse_args(Args, undefined, undefined, undefined, undefined, undefined, undefined, undefined, false).

parse_args([], Hours, Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned) ->
    case {Hours, Minutes, Seconds, Fraction, Sign, DiffHours} of
        {undefined, _, _, _, _, _} -> usage("missing -hours");
        {_, undefined, _, _, _, _} -> usage("missing -minutes");
        {_, _, undefined, _, _, _} -> usage("missing -seconds");
        {_, _, _, undefined, _, _} -> usage("missing -fraction");
        {_, _, _, _, undefined, _} -> usage("missing -sign");
        {_, _, _, _, _, undefined} -> usage("missing -diff-hours");
        _ -> {Hours, Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned}
    end;
parse_args(["-hours", V | Rest], _, Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, list_to_integer(V), Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned);
parse_args(["-minutes", V | Rest], Hours, _, Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, Hours, list_to_integer(V), Seconds, Fraction, Sign, DiffHours, DiffMinutes, Aligned);
parse_args(["-seconds", V | Rest], Hours, Minutes, _, Fraction, Sign, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, Hours, Minutes, list_to_integer(V), Fraction, Sign, DiffHours, DiffMinutes, Aligned);
parse_args(["-fraction", V | Rest], Hours, Minutes, Seconds, _, Sign, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, Hours, Minutes, Seconds, list_to_integer(V), Sign, DiffHours, DiffMinutes, Aligned);
parse_args(["-sign", V | Rest], Hours, Minutes, Seconds, Fraction, _, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, Hours, Minutes, Seconds, Fraction, list_to_atom(V), DiffHours, DiffMinutes, Aligned);
parse_args(["-diff-hours", V | Rest], Hours, Minutes, Seconds, Fraction, Sign, _, DiffMinutes, Aligned) ->
    parse_args(Rest, Hours, Minutes, Seconds, Fraction, Sign, list_to_integer(V), DiffMinutes, Aligned);
parse_args(["-diff-minutes", V | Rest], Hours, Minutes, Seconds, Fraction, Sign, DiffHours, _, Aligned) ->
    parse_args(Rest, Hours, Minutes, Seconds, Fraction, Sign, DiffHours, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Hours, Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, _) ->
    parse_args(Rest, Hours, Minutes, Seconds, Fraction, Sign, DiffHours, DiffMinutes, true);
parse_args([Unknown | _], _, _, _, _, _, _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_time_of_day_and_diff_and_fraction_encoding.erl -hours <int> -minutes <int> -seconds <int> -fraction <int> -sign <positive|negative> -diff-hours <int> [-diff-minutes <int>] [-aligned]~n",
        [Msg]),
    halt(1).
