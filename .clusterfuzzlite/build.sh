#!/bin/bash

go get github.com/AdamKorcz/go-118-fuzz-build/testing@2b5cbb29f3e2e08ef2032ac4dc88a40a3a1e9e5f

# TODO @pandatix find why these targets don't want to work
# compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzGeneratedValid                         fuzz_generated_valid
# compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzParseABNF                              fuzz_parse_abnf
# compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzGeneratedABNF                          fuzz_generated_abnf

compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzRegex                                  fuzz_regex
compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzRawGrammarToTransitionGraph            fuzz_raw_grammar_to_transition_graph
compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzGeneratedGrammarToTransitionGraph      fuzz_generated_grammar_to_transition_graph
compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzRawGrammarExhaustiveCombinations       fuzz_raw_grammar_exhaustive_combinations
compile_native_go_fuzzer github.com/pandatix/go-abnf FuzzGeneratedGrammarExhaustiveCombinations fuzz_generated_grammar_exhaustive_combinations
