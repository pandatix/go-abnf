package goabnf

var (
	inf int = -1

	// coreRules are the core rules specified in RFC 5234 Section 8.1
	coreRules = map[string]*rule{
		alpha.name:  alpha,
		bit.name:    bit,
		char.name:   char,
		cr.name:     cr,
		crlf.name:   crlf,
		ctl.name:    ctl,
		digit.name:  digit,
		dquote.name: dquote,
		hexdig.name: hexdig,
		htab.name:   htab,
		lf.name:     lf,
		lwsp.name:   lwsp,
		octet.name:  octet,
		sp.name:     sp,
		vchar.name:  vchar,
		wsp.name:    wsp,
	}

	// ALPHA = %x41-5A / %x61-7A
	alpha = &rule{
		name: "ALPHA",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"41", "5A"},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"61", "7A"},
							},
						},
					},
				},
			},
		},
	}

	// BIT = "0" / "1"
	bit = &rule{
		name: "BIT",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'0'},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'1'},
							},
						},
					},
				},
			},
		},
	}

	// CHAR = %x01-7F
	char = &rule{
		name: "CHAR",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"01", "7F"},
							},
						},
					},
				},
			},
		},
	}

	// CR = %x0D
	cr = &rule{
		name: "CR",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statSeries,
								elems:  []string{"0D"},
							},
						},
					},
				},
			},
		},
	}

	// CRLF = CR LF
	crlf = &rule{
		name: "CRLF",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "CR",
							},
						}, {
							min: 1,
							max: 1,
							element: elemRulename{
								name: "LF",
							},
						},
					},
				},
			},
		},
	}

	// CTL = %x00-1F / %x7F
	ctl = &rule{
		name: "CTL",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"00", "1F"},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statSeries,
								elems:  []string{"7F"},
							},
						},
					},
				},
			},
		},
	}

	// DIGIT = %x30-39
	digit = &rule{
		name: "DIGIT",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"30", "39"},
							},
						},
					},
				},
			},
		},
	}

	// DQUOTE = %x22
	dquote = &rule{
		name: "DQUOTE",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statSeries,
								elems:  []string{"22"},
							},
						},
					},
				},
			},
		},
	}

	// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
	hexdig = &rule{
		name: "HEXDIG",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "DIGIT",
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'A'},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'B'},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'C'},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'D'},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'E'},
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'F'},
							},
						},
					},
				},
			},
		},
	}

	// HTAB = %x09
	htab = &rule{
		name: "HTAB",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statSeries,
								elems:  []string{"09"},
							},
						},
					},
				},
			},
		},
	}

	// LF = %x0A
	lf = &rule{
		name: "LF",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statSeries,
								elems:  []string{"0A"},
							},
						},
					},
				},
			},
		},
	}

	// LWSP = *(WSP / CRLF WSP)
	lwsp = &rule{
		name: "LWSP",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "WSP",
													},
												},
											},
										}, {
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "CRLF",
													},
												}, {
													min: 1,
													max: 1,
													element: elemRulename{
														name: "WSP",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// OCTET = %x00-FF
	octet = &rule{
		name: "OCTET",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"00", "FF"},
							},
						},
					},
				},
			},
		},
	}

	// SP = %x20
	sp = &rule{
		name: "SP",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statSeries,
								elems:  []string{"20"},
							},
						},
					},
				},
			},
		},
	}

	// VCHAR = %x21-7E
	vchar = &rule{
		name: "VCHAR",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemNumVal{
								base:   "x",
								status: statRange,
								elems:  []string{"21", "7E"},
							},
						},
					},
				},
			},
		},
	}

	// WSP = SP / HTAB
	wsp = &rule{
		name: "WSP",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "SP",
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "HTAB",
							},
						},
					},
				},
			},
		},
	}
)

var (
	abnfRulelist = &rule{
		name: "rulelist",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "rule",
													},
												},
											},
										}, {
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 0,
																			max: inf,
																			element: elemRulename{
																				name: "WSP",
																			},
																		}, {
																			min: 1,
																			max: 1,
																			element: elemRulename{
																				name: "c-nl",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfRule = &rule{
		name: "rule",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "rulename",
							},
						}, {
							min: 1,
							max: 1,
							element: elemRulename{
								name: "defined-as",
							},
						}, {
							min: 1,
							max: 1,
							element: elemRulename{
								name: "elements",
							},
						}, {
							min: 1,
							max: 1,
							element: elemRulename{
								name: "c-nl",
							},
						},
					},
				},
			},
		},
	}

	abnfRulename = &rule{
		name: "rulename",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "ALPHA",
							},
						}, {
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "ALPHA",
													},
												},
											},
										}, {
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "DIGIT",
													},
												},
											},
										}, {
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemCharVal{
														values: []rune{'-'},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfDefinedAs = &rule{
		name: "defined-as",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 0,
							max: inf,
							element: elemRulename{
								name: "c-wsp",
							},
						}, {
							min: 1,
							max: 1,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemCharVal{
														values: []rune{'='},
													},
												},
											},
										}, {
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemCharVal{
														values: []rune{'=', '/'},
													},
												},
											},
										},
									},
								},
							},
						}, {
							min: 0,
							max: inf,
							element: elemRulename{
								name: "c-wsp",
							},
						},
					},
				},
			},
		},
	}

	abnfElements = &rule{
		name: "elements",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "alternation",
							},
						}, {
							min: 0,
							max: inf,
							element: elemRulename{
								name: "WSP",
							},
						},
					},
				},
			},
		},
	}

	abnfCWsp = &rule{
		name: "c-wsp",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "WSP",
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "c-nl",
													},
												}, {
													min: 1,
													max: 1,
													element: elemRulename{
														name: "WSP",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfCNl = &rule{
		name: "c-nl",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "comment",
							},
						},
					},
				}, {
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "CRLF",
							},
						},
					},
				},
			},
		},
	}

	abnfComment = &rule{
		name: "comment",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{';'},
							},
						},
						{
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "WSP",
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "VCHAR",
													},
												},
											},
										},
									},
								},
							},
						},
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "CRLF",
							},
						},
					},
				},
			},
		},
	}

	abnfAlternation = &rule{
		name: "alternation",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "concatenation",
							},
						},
						{
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 0,
													max: inf,
													element: elemRulename{
														name: "c-wsp",
													},
												},
												{
													min: 1,
													max: 1,
													element: elemCharVal{
														values: []rune{'/'},
													},
												},
												{
													min: 0,
													max: inf,
													element: elemRulename{
														name: "c-wsp",
													},
												},
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "concatenation",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfConcatenation = &rule{
		name: "concatenation",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "repetition",
							},
						},
						{
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: inf,
													element: elemRulename{
														name: "c-wsp",
													},
												},
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "repetition",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfRepetition = &rule{
		name: "repetition",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemOption{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "repeat",
													},
												},
											},
										},
									},
								},
							},
						},
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "element",
							},
						},
					},
				},
			},
		},
	}

	abnfRepeat = &rule{
		name: "repeat",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: inf,
							element: elemRulename{
								name: "DIGIT",
							},
						},
					},
				},
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 0,
													max: inf,
													element: elemRulename{
														name: "DIGIT",
													},
												},
												{
													min: 1,
													max: 1,
													element: elemCharVal{
														values: []rune{'*'},
													},
												},
												{
													min: 0,
													max: inf,
													element: elemRulename{
														name: "DIGIT",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfElement = &rule{
		name: "element",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "rulename",
							},
						},
					},
				},
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "group",
							},
						},
					},
				},
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "option",
							},
						},
					},
				},
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "char-val",
							},
						},
					},
				},
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "num-val",
							},
						},
					},
				},
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "prose-val",
							},
						},
					},
				},
			},
		},
	}

	abnfGroup = &rule{
		name: "group",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'('},
							},
						},
						{
							min: 0,
							max: inf,
							element: elemRulename{
								name: "c-wsp",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "alternation",
							},
						},
						{
							min: 0,
							max: inf,
							element: elemRulename{
								name: "c-wsp",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{')'},
							},
						},
					},
				},
			},
		},
	}

	abnfOption = &rule{
		name: "option",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'['},
							},
						},
						{
							min: 0,
							max: inf,
							element: elemRulename{
								name: "c-wsp",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "alternation",
							},
						},
						{
							min: 0,
							max: inf,
							element: elemRulename{
								name: "c-wsp",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{']'},
							},
						},
					},
				},
			},
		},
	}

	abnfCharVal = &rule{
		name: "char-val",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "DQUOTE",
							},
						},
						{
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemNumVal{
														base:   "x",
														status: statRange,
														elems:  []string{"20", "21"},
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemNumVal{
														base:   "x",
														status: statRange,
														elems:  []string{"23", "7E"},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							min: 1,
							max: 1,
							element: elemRulename{
								name: "DQUOTE",
							},
						},
					},
				},
			},
		},
	}

	abnfNumVal = &rule{
		name: "num-val",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'%'},
							},
						},
						{
							min: 1,
							max: 1,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "bin-val",
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "dec-val",
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemRulename{
														name: "hex-val",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfBinVal = &rule{
		name: "bin-val",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'b'},
							},
						},
						{
							min: 1,
							max: inf,
							element: elemRulename{
								name: "BIT",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemOption{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: inf,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 1,
																			max: 1,
																			element: elemCharVal{
																				values: []rune{'.'},
																			},
																		},
																		{
																			min: 1,
																			max: inf,
																			element: elemRulename{
																				name: "BIT",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 1,
																			max: 1,
																			element: elemCharVal{
																				values: []rune{'-'},
																			},
																		},
																		{
																			min: 1,
																			max: inf,
																			element: elemRulename{
																				name: "BIT",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfDecVal = &rule{
		name: "dec-val",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'d'},
							},
						},
						{
							min: 1,
							max: inf,
							element: elemRulename{
								name: "DIGIT",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemOption{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: inf,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 1,
																			max: 1,
																			element: elemCharVal{
																				values: []rune{'.'},
																			},
																		},
																		{
																			min: 1,
																			max: inf,
																			element: elemRulename{
																				name: "DIGIT",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 1,
																			max: 1,
																			element: elemCharVal{
																				values: []rune{'-'},
																			},
																		},
																		{
																			min: 1,
																			max: inf,
																			element: elemRulename{
																				name: "DIGIT",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfHexVal = &rule{
		name: "hex-val",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'x'},
							},
						},
						{
							min: 1,
							max: inf,
							element: elemRulename{
								name: "HEXDIG",
							},
						},
						{
							min: 1,
							max: 1,
							element: elemOption{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: inf,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 1,
																			max: 1,
																			element: elemCharVal{
																				values: []rune{'.'},
																			},
																		},
																		{
																			min: 1,
																			max: inf,
																			element: elemRulename{
																				name: "HEXDIG",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemGroup{
														alternation: alternation{
															concatenations: []concatenation{
																{
																	repetitions: []repetition{
																		{
																			min: 1,
																			max: 1,
																			element: elemCharVal{
																				values: []rune{'-'},
																			},
																		},
																		{
																			min: 1,
																			max: inf,
																			element: elemRulename{
																				name: "HEXDIG",
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	abnfProseVal = &rule{
		name: "prose-val",
		alternation: alternation{
			concatenations: []concatenation{
				{
					repetitions: []repetition{
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'<'},
							},
						},
						{
							min: 0,
							max: inf,
							element: elemGroup{
								alternation: alternation{
									concatenations: []concatenation{
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemNumVal{
														base:   "x",
														status: statRange,
														elems:  []string{"20", "3D"},
													},
												},
											},
										},
										{
											repetitions: []repetition{
												{
													min: 1,
													max: 1,
													element: elemNumVal{
														base:   "x",
														status: statRange,
														elems:  []string{"3F", "7E"},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							min: 1,
							max: 1,
							element: elemCharVal{
								values: []rune{'>'},
							},
						},
					},
				},
			},
		},
	}
)
