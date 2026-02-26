#!/usr/bin/env escript
%% Encode a named INTEGER type using APER or UPER from Erlang/OTP compiled modules.
%%
%% Usage:
%%   escript encode_integer.erl -name <TypeName> -value <N> [-aligned]
%%
%% Flags:
%%   -name <TypeName>  ASN.1 type name (e.g. 'INTEGER-0-100-FALSE')
%%   -value <N>        integer value to encode (e.g. 50, -100)
%%   -aligned          use APER (aligned PER); omit for UPER (default)
%%
%% Output: hex-encoded PER bytes on stdout

main(Args) ->
    {Name, Value, Aligned} = parse_args(Args),
    case {Name, Value} of
        {undefined, _} ->
            io:fwrite("error: missing -name~n"),
            halt(1);
        {_, undefined} ->
            io:fwrite("error: missing -value~n"),
            halt(1);
        _ ->
            encode_and_print(Name, Value, Aligned)
    end.

parse_args(Args) ->
    parse_args(Args, undefined, undefined, false).

parse_args([], Name, Value, Aligned) ->
    {Name, Value, Aligned};
parse_args(["-name", Name | Rest], _, Value, Aligned) ->
    parse_args(Rest, Name, Value, Aligned);
parse_args(["-value", ValueStr | Rest], Name, _, Aligned) ->
    Value = list_to_integer(ValueStr),
    parse_args(Rest, Name, Value, Aligned);
parse_args(["-aligned" | Rest], Name, Value, _) ->
    parse_args(Rest, Name, Value, true);
parse_args([_ | Rest], Name, Value, Aligned) ->
    parse_args(Rest, Name, Value, Aligned).

encode_and_print(NameStr, Value, Aligned) ->
    % Load the compiled INTEGERS beam from appropriate directory
    Encoding = case Aligned of true -> aper; false -> uper end,
    BeamDir = atom_to_list(Encoding),
    code:add_patha(BeamDir),
    
    % Convert type name string to atom
    TypeAtom = list_to_atom(NameStr),
    
    % Encode using the loaded INTEGERS module
    % The INTEGERS module has an encode/2 function: encode(TypeAtom, Value)
    case 'INTEGERS':encode(TypeAtom, Value) of
        {ok, Bytes} ->
            print_hex(Bytes);
        {error, Reason} ->
            io:fwrite(standard_error, "Encode error: ~p~n", [Reason]),
            halt(1)
    end.

print_hex(Bytes) ->
    Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || B <- binary_to_list(Bytes)]),
    io:fwrite("~s~n", [Hex]),
    halt(0).

