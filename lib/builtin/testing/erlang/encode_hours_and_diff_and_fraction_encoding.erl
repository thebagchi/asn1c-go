#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a HOURS-AND-DIFF-AND-FRACTION-ENCODING SEQUENCE using APER or
%% UPER from Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_hours_and_diff_and_fraction_encoding.erl -local-hours <int> -fraction <int> -sign <positive|negative> -diff-hours <int> [-diff-minutes <int>] [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {LocalHours, Fraction, Sign, DiffHours, DiffMinutes, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    DiffMinutesVal = case DiffMinutes of undefined -> asn1_NOVALUE; _ -> DiffMinutes end,
    TimeDifference = {'TIME-DIFFERENCE', Sign, DiffHours, DiffMinutesVal},
    Value = {'HOURS-AND-DIFF-AND-FRACTION-ENCODING', LocalHours, Fraction, TimeDifference},
    case 'TIME-DIFFERENCE':encode('HOURS-AND-DIFF-AND-FRACTION-ENCODING', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

parse_args(Args) ->
    parse_args(Args, undefined, undefined, undefined, undefined, undefined, false).

parse_args([], LocalHours, Fraction, Sign, DiffHours, DiffMinutes, Aligned) ->
    case {LocalHours, Fraction, Sign, DiffHours} of
        {undefined, _, _, _} -> usage("missing -local-hours");
        {_, undefined, _, _} -> usage("missing -fraction");
        {_, _, undefined, _} -> usage("missing -sign");
        {_, _, _, undefined} -> usage("missing -diff-hours");
        _ -> {LocalHours, Fraction, Sign, DiffHours, DiffMinutes, Aligned}
    end;
parse_args(["-local-hours", V | Rest], _, Fraction, Sign, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, list_to_integer(V), Fraction, Sign, DiffHours, DiffMinutes, Aligned);
parse_args(["-fraction", V | Rest], LocalHours, _, Sign, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, LocalHours, list_to_integer(V), Sign, DiffHours, DiffMinutes, Aligned);
parse_args(["-sign", V | Rest], LocalHours, Fraction, _, DiffHours, DiffMinutes, Aligned) ->
    parse_args(Rest, LocalHours, Fraction, list_to_atom(V), DiffHours, DiffMinutes, Aligned);
parse_args(["-diff-hours", V | Rest], LocalHours, Fraction, Sign, _, DiffMinutes, Aligned) ->
    parse_args(Rest, LocalHours, Fraction, Sign, list_to_integer(V), DiffMinutes, Aligned);
parse_args(["-diff-minutes", V | Rest], LocalHours, Fraction, Sign, DiffHours, _, Aligned) ->
    parse_args(Rest, LocalHours, Fraction, Sign, DiffHours, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], LocalHours, Fraction, Sign, DiffHours, DiffMinutes, _) ->
    parse_args(Rest, LocalHours, Fraction, Sign, DiffHours, DiffMinutes, true);
parse_args([Unknown | _], _, _, _, _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_hours_and_diff_and_fraction_encoding.erl -local-hours <int> -fraction <int> -sign <positive|negative> -diff-hours <int> [-diff-minutes <int>] [-aligned]~n",
        [Msg]),
    halt(1).
