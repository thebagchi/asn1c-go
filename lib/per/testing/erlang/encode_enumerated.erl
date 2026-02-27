#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a named ENUMERATED type from ENUMERATEDS module using APER or UPER.
%%
%% Usage:
%%   escript encode_enumerated.erl -name <TypeName> -value <MemberName> [-aligned]
%%
%% Flags:
%%   -name <TypeName>      ASN.1 type name (e.g. 'ENUM-4-0-FALSE')
%%   -value <MemberName>   enumeration member name (e.g. 'm-1')
%%   -aligned              use APER (aligned PER); omit for UPER (default)
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    {Name, Value, Aligned} = parse_args(Args),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    TypeAtom = list_to_atom(Name),
    ValueAtom = list_to_atom(Value),
    case 'ENUMERATEDS':encode(TypeAtom, ValueAtom) of
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

parse_args([], Name, Value, Aligned) ->
    case {Name, Value} of
        {undefined, _} -> usage("missing -name");
        {_, undefined} -> usage("missing -value");
        _ -> {Name, Value, Aligned}
    end;
parse_args(["-name", N | Rest], _, Value, Aligned) ->
    parse_args(Rest, N, Value, Aligned);
parse_args(["-value", V | Rest], Name, _, Aligned) ->
    parse_args(Rest, Name, V, Aligned);
parse_args(["-aligned" | Rest], Name, Value, _) ->
    parse_args(Rest, Name, Value, true);
parse_args([Unknown | _], _, _, _) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_enumerated.erl -name <TypeName> -value <MemberName> [-aligned]~n",
        [Msg]),
    halt(1).
