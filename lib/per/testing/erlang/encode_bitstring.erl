#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a named BIT STRING type from BITSTRINGS module using APER or UPER.
%%
%% Usage:
%%   escript encode_bitstring.erl -name <TypeName> -length <N> [-aligned]
%%
%% Flags:
%%   -name <TypeName>  ASN.1 type name to encode (e.g. 'BITSTRING-NULL-NULL-FALSE')
%%   -length <N>       bit string length in bits
%%   -aligned          use APER (aligned PER); omit for UPER (default)
%%
%% Examples:
%%   escript encode_bitstring.erl -name 'BITSTRING-NULL-NULL-FALSE' -length 16384          # UPER
%%   escript encode_bitstring.erl -name 'BITSTRING-NULL-NULL-FALSE' -length 16384 -aligned  # APER
%%
%% The script must be run from the erlang/ directory so it can locate
%% the aper/ or uper/ sub-directory containing the compiled BITSTRINGS beam.

-mode(compile).

main(Args) ->
    {Name, Length, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Val = gen_alt(Length),
    case 'BITSTRINGS':encode(list_to_atom(Name), Val) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

%% Generate alternating 01010101... bitstring of Length bits (0x55 per byte).
gen_alt(Length) ->
    FullBytes = Length div 8,
    RemBits   = Length rem 8,
    Base      = binary:copy(<<85>>, FullBytes),
    case RemBits of
        0 -> Base;
        _ -> <<Base/bitstring, (85 bsr (8 - RemBits)):RemBits>>
    end.

parse_args(Args) ->
    parse_args(Args, undefined, undefined, false).

parse_args([], Name, Length, Aligned) ->
    case {Name, Length} of
        {undefined, _} -> usage("missing -name");
        {_, undefined} -> usage("missing -length");
        _ -> {Name, Length, Aligned}
    end;
parse_args(["-name", N | Rest], _, Length, Aligned) ->
    parse_args(Rest, N, Length, Aligned);
parse_args(["-length", L | Rest], Name, _, Aligned) ->
    parse_args(Rest, Name, list_to_integer(L), Aligned);
parse_args(["-aligned" | Rest], Name, Length, _) ->
    parse_args(Rest, Name, Length, true);
parse_args([Unknown | _], _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_bitstring.erl -name <TypeName> -length <N> [-aligned]~n",
        [Msg]),
    halt(1).
