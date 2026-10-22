#!/usr/bin/env escript
%% Encode many values of one module with Erlang/OTP asn1ct output.
%%
%% Usage:
%%   escript encode_batch.escript <beam dir> <Module>
%%
%% The beam dir holds <Module>.beam compiled with the per or uper option.
%% Standard input holds one value a line: <Type> TAB <Erlang expression>. An
%% expression, not only a term, so that a bit string can be written <<1, 2:3>>.
%% A line of output follows each line of input: hex-encoded PER octets, or
%% "error ..." when OTP refuses the value.

main([Dir, Module]) ->
    code:add_patha(Dir),
    loop(list_to_atom(Module)).

loop(Module) ->
    case io:get_line("") of
        eof -> ok;
        Line ->
            encode(Module, string:trim(Line, trailing, "\n")),
            loop(Module)
    end.

encode(Module, Line) ->
    [Type, Text] = string:split(Line, "\t"),
    {ok, Tokens, _} = erl_scan:string(Text ++ "."),
    {ok, Exprs} = erl_parse:parse_exprs(Tokens),
    {value, Term, _} = erl_eval:exprs(Exprs, []),
    try Module:encode(list_to_atom(Type), Term) of
        {ok, Bytes} ->
            io:fwrite("~s~n", [lists:flatten([io_lib:format("~2.16.0b", [B]) || B <- binary_to_list(Bytes)])]);
        Other ->
            io:fwrite("error ~w~n", [Other])
    catch
        Class:Reason -> io:fwrite("error ~w ~w~n", [Class, Reason])
    end.
