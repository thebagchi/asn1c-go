#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a RealType {mantissa, base, exponent} SEQUENCE using APER or UPER
%% from Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_real_type.erl -mantissa <int> -base <int> -exponent <int> [-aligned]
%%
%% Flags:
%%   -mantissa <int>  mantissa component
%%   -base     <int>  base component (2 or 10)
%%   -exponent <int>  exponent component
%%   -aligned         use APER (aligned PER); omit for UPER (default)
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Mantissa, Base, Exponent, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Value = {'RealType', Mantissa, Base, Exponent},
    case 'REAL-TYPE':encode('RealType', Value) of
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

parse_args([], Mantissa, Base, Exponent, Aligned) ->
    case {Mantissa, Base, Exponent} of
        {undefined, _, _} -> usage("missing -mantissa");
        {_, undefined, _} -> usage("missing -base");
        {_, _, undefined} -> usage("missing -exponent");
        _ -> {Mantissa, Base, Exponent, Aligned}
    end;
parse_args(["-mantissa", V | Rest], _, Base, Exponent, Aligned) ->
    parse_args(Rest, list_to_integer(V), Base, Exponent, Aligned);
parse_args(["-base", V | Rest], Mantissa, _, Exponent, Aligned) ->
    parse_args(Rest, Mantissa, list_to_integer(V), Exponent, Aligned);
parse_args(["-exponent", V | Rest], Mantissa, Base, _, Aligned) ->
    parse_args(Rest, Mantissa, Base, list_to_integer(V), Aligned);
parse_args(["-aligned" | Rest], Mantissa, Base, Exponent, _) ->
    parse_args(Rest, Mantissa, Base, Exponent, true);
parse_args([Unknown | _], _, _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_real_type.erl -mantissa <int> -base <int> -exponent <int> [-aligned]~n",
        [Msg]),
    halt(1).
