#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Encode a DURATION-EQUIVALENT SEQUENCE using APER or UPER from Erlang/OTP
%% compiled modules. Every field is optional; omit a flag to leave the
%% corresponding component absent (asn1_NOVALUE).
%%
%% Usage:
%%   escript encode_duration_equivalent.erl [-years <int>] [-months <int>] [-weeks <int>] [-days <int>] [-hours <int>] [-minutes <int>] [-seconds <int>] [-number-of-digits <int>] [-fractional-value <int>] [-aligned]
%%
%% Output: hex-encoded PER bytes on stdout

-mode(compile).

main(Args) ->
    Opts = parse_args(Args, #{aligned => false}),
    Aligned = maps:get(aligned, Opts),
    Encoding = case Aligned of true -> "aper"; false -> "uper" end,
    ScriptDir = filename:dirname(escript:script_name()),
    BeamDir = filename:join(ScriptDir, Encoding),
    true = code:add_path(BeamDir),
    Get = fun(Key) -> maps:get(Key, Opts, asn1_NOVALUE) end,
    FractionalPart = case {maps:is_key(number_of_digits, Opts), maps:is_key(fractional_value, Opts)} of
        {true, true} ->
            {'DURATION-EQUIVALENT_fractional-part',
                maps:get(number_of_digits, Opts), maps:get(fractional_value, Opts)};
        _ ->
            asn1_NOVALUE
    end,
    Value = {'DURATION-EQUIVALENT',
        Get(years), Get(months), Get(weeks), Get(days),
        Get(hours), Get(minutes), Get(seconds), FractionalPart},
    case 'TIME-DIFFERENCE':encode('DURATION-EQUIVALENT', Value) of
        {ok, Enc} ->
            Bin = iolist_to_binary(Enc),
            Hex = lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]),
            io:format("~s~n", [Hex]);
        {error, Reason} ->
            io:format(standard_error, "encode error: ~p~n", [Reason]),
            halt(1)
    end.

parse_args([], Opts) ->
    Opts;
parse_args(["-years", V | Rest], Opts) ->
    parse_args(Rest, Opts#{years => list_to_integer(V)});
parse_args(["-months", V | Rest], Opts) ->
    parse_args(Rest, Opts#{months => list_to_integer(V)});
parse_args(["-weeks", V | Rest], Opts) ->
    parse_args(Rest, Opts#{weeks => list_to_integer(V)});
parse_args(["-days", V | Rest], Opts) ->
    parse_args(Rest, Opts#{days => list_to_integer(V)});
parse_args(["-hours", V | Rest], Opts) ->
    parse_args(Rest, Opts#{hours => list_to_integer(V)});
parse_args(["-minutes", V | Rest], Opts) ->
    parse_args(Rest, Opts#{minutes => list_to_integer(V)});
parse_args(["-seconds", V | Rest], Opts) ->
    parse_args(Rest, Opts#{seconds => list_to_integer(V)});
parse_args(["-number-of-digits", V | Rest], Opts) ->
    parse_args(Rest, Opts#{number_of_digits => list_to_integer(V)});
parse_args(["-fractional-value", V | Rest], Opts) ->
    parse_args(Rest, Opts#{fractional_value => list_to_integer(V)});
parse_args(["-aligned" | Rest], Opts) ->
    parse_args(Rest, Opts#{aligned => true});
parse_args([Unknown | _], _Opts) ->
    usage(io_lib:format("unknown argument: ~s", [Unknown])).

usage(Msg) ->
    io:format(standard_error,
        "error: ~s~nUsage: escript encode_duration_equivalent.erl [-years <int>] [-months <int>] [-weeks <int>] [-days <int>] [-hours <int>] [-minutes <int>] [-seconds <int>] [-number-of-digits <int>] [-fractional-value <int>] [-aligned]~n",
        [Msg]),
    halt(1).
