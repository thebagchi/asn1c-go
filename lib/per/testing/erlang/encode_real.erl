#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a REAL value using APER or UPER from Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_real.erl -value <float> [-aligned]
%%
%% Flags:
%%   -value <float>  real value to encode (e.g. 3.14, -1.5)
%%   -aligned        use APER (aligned PER); omit for UPER (default)
%%
%% The Erlang ASN.1 REAL encoder requires {Mantissa, Base, Exponent} tuples.
%% This script converts IEEE 754 floats to base-2 canonical form.
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Value, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    case 'REALS':encode('FLOAT-64', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

%% Convert a float to {Mantissa, 2, Exponent} tuple for ASN.1 REAL encoding.
%% Zero is represented as {0, 10, 0} per Erlang asn1 convention.
float_to_real(0.0) ->
    {0, 10, 0};
float_to_real(F) ->
    <<Sign:1, BExp:11, Frac:52>> = <<F/float>>,
    case BExp of
        0 ->
            %% Subnormal: exponent = -1022, implicit bit = 0
            RawMantissa = Frac,
            Exponent = -1022 - 52;
        _ ->
            %% Normal: implicit leading 1
            RawMantissa = (1 bsl 52) bor Frac,
            Exponent = BExp - 1023 - 52
    end,
    Mantissa = case Sign of
        0 -> RawMantissa;
        1 -> -RawMantissa
    end,
    %% Normalize: make mantissa odd (strip trailing zeros)
    {M2, E2} = normalize(Mantissa, Exponent),
    {M2, 2, E2}.

normalize(0, E) -> {0, E};
normalize(M, E) when M rem 2 =:= 0 ->
    normalize(M div 2, E + 1);
normalize(M, E) ->
    {M, E}.

parse_args(Args) ->
    parse_args(Args, undefined, false).

parse_args([], Value, Aligned) ->
    case Value of
        undefined -> usage("missing -value");
        _ -> {Value, Aligned}
    end;
parse_args(["-value", ValStr | Rest], _, Aligned) ->
    Value = parse_float(ValStr),
    parse_args(Rest, float_to_real(Value), Aligned);
parse_args(["-aligned" | Rest], Value, _) ->
    parse_args(Rest, Value, true);
parse_args([Unknown | _], _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

parse_float(Str) ->
    case string:to_float(Str) of
        {error, no_float} ->
            %% Must be an integer string; append ".0"
            list_to_float(Str ++ ".0");
        {F, _} ->
            F
    end.

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_real.erl -value <float> [-aligned]~n",
        [Msg]),
    halt(1).
