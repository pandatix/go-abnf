package goabnf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_U_ParseABNF(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input       string
		ExpectedGST *GST
		ExpectedErr error
	}{
		// "example-rule": {
		// 	Input: `example  = some-rule ("a" / "b")`,
		// 	ExpectedGST: &Grammar{
		// 		rulemap: map[string]*rule{
		// 			"example": {
		// 				name: "example",
		// 				alternation: alternation{
		// 					concatenations: []concatenation{
		// 						{
		// 							repetitions: []repetition{
		// 								{
		// 									min: 1,
		// 									max: 1,
		// 									element: elemRulename{
		// 										name: "some-rule",
		// 									},
		// 								}, {
		// 									min: 1,
		// 									max: 1,
		// 									element: elemGroup{
		// 										alternation: alternation{
		// 											concatenations: []concatenation{
		// 												{
		// 													repetitions: []repetition{
		// 														{
		// 															min: 1,
		// 															max: 1,
		// 															element: elemCharVal{
		// 																values: []rune{'a'},
		// 															},
		// 														},
		// 													},
		// 												}, {
		// 													repetitions: []repetition{
		// 														{
		// 															min: 1,
		// 															max: 1,
		// 															element: elemCharVal{
		// 																values: []rune{'b'},
		// 															},
		// 														},
		// 													},
		// 												},
		// 											},
		// 										},
		// 									},
		// 								},
		// 							},
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	ExpectedErr: nil,
		// },
		"aaaaaaaa": {
			Input: "a = \"a\"\r\n",
			ExpectedGST: &GST{
				Sub: []*Possibility{
					{
						Sub: []*Possibility{
							{
								Sub: []*Possibility{
									{
										Sub:       []*Possibility{},
										MatchRule: "ALPHA",
										Start:     0,
										End:       1,
									},
								},
								MatchRule: "rulename",
								Start:     0,
								End:       1,
							}, {
								Sub: []*Possibility{
									{
										Sub:       []*Possibility{},
										MatchRule: "c-wsp",
										Start:     1,
										End:       2,
									}, {
										Sub:       []*Possibility{},
										MatchRule: "", // XXX ? is a char-val
										Start:     2,
										End:       3,
									}, {
										Sub:       []*Possibility{},
										MatchRule: "c-wsp",
										Start:     3,
										End:       4,
									},
								},
								MatchRule: "defined-as",
								Start:     1,
								End:       3,
							}, {
								Sub: []*Possibility{
									{
										Sub: []*Possibility{
											{
												Sub: []*Possibility{
													{
														Sub: []*Possibility{
															{
																Sub: []*Possibility{
																	{
																		Sub: []*Possibility{
																			{
																				Sub: []*Possibility{
																					{
																						Sub: []*Possibility{
																							{
																								Sub: []*Possibility{
																									{
																										Sub:       []*Possibility{},
																										MatchRule: "", // XXX ? is a char-val
																										Start:     4,
																										End:       5,
																									},
																								},
																								MatchRule: "DQUOTE",
																								Start:     4,
																								End:       5,
																							}, {
																								Sub:       []*Possibility{},
																								MatchRule: "", // XXX ?
																								Start:     5,
																								End:       6,
																							}, {
																								Sub: []*Possibility{
																									{
																										Sub:       []*Possibility{},
																										MatchRule: "", // XXX ? is a char-val
																										Start:     6,
																										End:       7,
																									},
																								},
																								MatchRule: "DQUOTE",
																								Start:     6,
																								End:       7,
																							},
																						},
																						MatchRule: "quoted-string",
																						Start:     4,
																						End:       7,
																					},
																				},
																				MatchRule: "case-insensitive-string",
																				Start:     4,
																				End:       7,
																			},
																		},
																		MatchRule: "char-val",
																		Start:     4,
																		End:       7,
																	},
																},
																MatchRule: "element",
																Start:     4,
																End:       7,
															},
														},
														MatchRule: "repetition",
														Start:     4,
														End:       7,
													},
												},
												MatchRule: "concatenation",
												Start:     4,
												End:       7,
											},
										},
										MatchRule: "alternation",
										Start:     4,
										End:       7,
									},
								},
								MatchRule: "elements",
								Start:     4,
								End:       7,
							}, {
								Sub: []*Possibility{
									{
										Sub: []*Possibility{
											{
												Sub:       []*Possibility{},
												MatchRule: "CR",
												Start:     7,
												End:       8,
											}, {
												Sub:       []*Possibility{},
												MatchRule: "LF",
												Start:     8,
												End:       9,
											},
										},
										MatchRule: "CRLF",
										Start:     7,
										End:       9,
									},
								},
								MatchRule: "c-nl",
								Start:     7,
								End:       9,
							},
						},
						MatchRule: "rule",
						Start:     0,
						End:       9,
					},
				},
				MatchRule: "rulelist",
				Start:     0,
				End:       9,
			},
			ExpectedErr: nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := ParseABNF([]byte(tt.Input))

			assert.Equal(tt.ExpectedGST, g)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func Test_U_Parse(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Input           string
		Grammar         *Grammar
		RootRulename    string
		ExpectedGrammar *Grammar
		ExpectedErr     error
	}{
		"char-val": {
			Input:           `"abc"`,
			Grammar:         ABNF,
			RootRulename:    "char-val",
			ExpectedGrammar: &Grammar{},
			ExpectedErr:     nil,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			g, err := Parse([]byte(tt.Input), tt.Grammar, tt.RootRulename)

			assert.Equal(tt.ExpectedGrammar, g)
			assert.Equal(tt.ExpectedErr, err)
		})
	}
}

func Test_U_Atob(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		Str         string
		Base        string
		ExpectedVal byte
	}{
		"0x30": {
			Str:         "3c",
			Base:        "x",
			ExpectedVal: 0x3c,
		},
		"0b10": {
			Str:         "10",
			Base:        "b",
			ExpectedVal: 0b10,
		},
		"0d56": {
			Str:         "56",
			Base:        "d",
			ExpectedVal: 56,
		},
	}

	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			assert := assert.New(t)

			val := atob(tt.Str, tt.Base)

			assert.Equal(tt.ExpectedVal, val)
		})
	}
}
