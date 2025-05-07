package goabnf

var (
	inf int = -1

	// coreRules are the core rules specified in RFC 5234 Section 8.1
	coreRules = map[string]*Rule{
		alpha.Name:  alpha,
		bit.Name:    bit,
		char.Name:   char,
		cr.Name:     cr,
		crlf.Name:   crlf,
		ctl.Name:    ctl,
		digit.Name:  digit,
		dquote.Name: dquote,
		hexdig.Name: hexdig,
		htab.Name:   htab,
		lf.Name:     lf,
		lwsp.Name:   lwsp,
		octet.Name:  octet,
		sp.Name:     sp,
		vchar.Name:  vchar,
		wsp.Name:    wsp,
	}

	// ALPHA = %x41-5A / %x61-7A
	alpha = &Rule{
		Name: "ALPHA",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x41, 0x5A},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x61, 0x7A},
							},
						},
					},
				},
			},
		},
	}

	// BIT = "0" / "1"
	bit = &Rule{
		Name: "BIT",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'0'},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'1'},
							},
						},
					},
				},
			},
		},
	}

	// CHAR = %x01-7F
	char = &Rule{
		Name: "CHAR",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x01, 0x7F},
							},
						},
					},
				},
			},
		},
	}

	// CR = %x0D
	cr = &Rule{
		Name: "CR",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatSeries,
								Elems:  []byte{0x0D},
							},
						},
					},
				},
			},
		},
	}

	// CRLF = CR LF
	crlf = &Rule{
		Name: "CRLF",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "CR",
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "LF",
							},
						},
					},
				},
			},
		},
	}

	// CTL = %x00-1F / %x7F
	ctl = &Rule{
		Name: "CTL",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x00, 0x1F},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatSeries,
								Elems:  []byte{0x7F},
							},
						},
					},
				},
			},
		},
	}

	// DIGIT = %x30-39
	digit = &Rule{
		Name: "DIGIT",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x30, 0x39},
							},
						},
					},
				},
			},
		},
	}

	// DQUOTE = %x22
	dquote = &Rule{
		Name: "DQUOTE",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatSeries,
								Elems:  []byte{0x22},
							},
						},
					},
				},
			},
		},
	}

	// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
	hexdig = &Rule{
		Name: "HEXDIG",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "DIGIT",
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'A'},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'B'},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'C'},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'D'},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'E'},
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'F'},
							},
						},
					},
				},
			},
		},
	}

	// HTAB = %x09
	htab = &Rule{
		Name: "HTAB",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatSeries,
								Elems:  []byte{0x09},
							},
						},
					},
				},
			},
		},
	}

	// LF = %x0A
	lf = &Rule{
		Name: "LF",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatSeries,
								Elems:  []byte{0x0A},
							},
						},
					},
				},
			},
		},
	}

	// LWSP = *(WSP / CRLF WSP)
	lwsp = &Rule{
		Name: "LWSP",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "WSP",
													},
												},
											},
										}, {
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "CRLF",
													},
												}, {
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "WSP",
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
	octet = &Rule{
		Name: "OCTET",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x00, 0xFF},
							},
						},
					},
				},
			},
		},
	}

	// SP = %x20
	sp = &Rule{
		Name: "SP",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatSeries,
								Elems:  []byte{0x20},
							},
						},
					},
				},
			},
		},
	}

	// VCHAR = %x21-7E
	vchar = &Rule{
		Name: "VCHAR",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemNumVal{
								Base:   "x",
								Status: StatRange,
								Elems:  []byte{0x21, 0x7E},
							},
						},
					},
				},
			},
		},
	}

	// WSP = SP / HTAB
	wsp = &Rule{
		Name: "WSP",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "SP",
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "HTAB",
							},
						},
					},
				},
			},
		},
	}
)

var (
	abnfRulelist = &Rule{
		Name: "rulelist",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "rule",
													},
												},
											},
										}, {
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 0,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "WSP", // Fixed according to Errata 3076
																			},
																		}, {
																			Min: 1,
																			Max: 1,
																			Element: ElemRulename{
																				Name: "c-nl",
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

	abnfRule = &Rule{
		Name: "rule",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "rulename",
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "defined-as",
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "elements",
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "c-nl",
							},
						},
					},
				},
			},
		},
	}

	abnfRulename = &Rule{
		Name: "rulename",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "ALPHA",
							},
						}, {
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "ALPHA",
													},
												},
											},
										}, {
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "DIGIT",
													},
												},
											},
										}, {
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemCharVal{
														Sensitive: false,
														Values:    []byte{'-'},
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

	abnfDefinedAs = &Rule{
		Name: "defined-as",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "c-wsp",
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemCharVal{
														Sensitive: false,
														Values:    []byte{'='},
													},
												},
											},
										}, {
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemCharVal{
														Sensitive: false,
														Values:    []byte{'=', '/'},
													},
												},
											},
										},
									},
								},
							},
						}, {
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "c-wsp",
							},
						},
					},
				},
			},
		},
	}

	abnfElements = &Rule{
		Name: "elements",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "alternation",
							},
						}, {
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "WSP", // Fixed according to Errata 2968
							},
						},
					},
				},
			},
		},
	}

	abnfCWsp = &Rule{
		Name: "c-wsp",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "WSP",
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "c-nl",
													},
												}, {
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "WSP",
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

	abnfCNl = &Rule{
		Name: "c-nl",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "comment",
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "CRLF",
							},
						},
					},
				},
			},
		},
	}

	abnfComment = &Rule{
		Name: "comment",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{';'},
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "WSP",
													},
												},
											},
										},
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "VCHAR",
													},
												},
											},
										},
									},
								},
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "CRLF",
							},
						},
					},
				},
			},
		},
	}

	abnfAlternation = &Rule{
		Name: "alternation",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "concatenation",
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 0,
													Max: inf,
													Element: ElemRulename{
														Name: "c-wsp",
													},
												},
												{
													Min: 1,
													Max: 1,
													Element: ElemCharVal{
														Sensitive: false,
														Values:    []byte{'/'},
													},
												},
												{
													Min: 0,
													Max: inf,
													Element: ElemRulename{
														Name: "c-wsp",
													},
												},
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "concatenation",
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

	abnfConcatenation = &Rule{
		Name: "concatenation",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "repetition",
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: inf,
													Element: ElemRulename{
														Name: "c-wsp",
													},
												},
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "repetition",
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

	abnfRepetition = &Rule{
		Name: "repetition",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemOption{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "repeat",
													},
												},
											},
										},
									},
								},
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "element",
							},
						},
					},
				},
			},
		},
	}

	abnfRepeat = &Rule{
		Name: "repeat",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: inf,
							Element: ElemRulename{
								Name: "DIGIT",
							},
						},
					},
				},
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 0,
													Max: inf,
													Element: ElemRulename{
														Name: "DIGIT",
													},
												},
												{
													Min: 1,
													Max: 1,
													Element: ElemCharVal{
														Sensitive: false,
														Values:    []byte{'*'},
													},
												},
												{
													Min: 0,
													Max: inf,
													Element: ElemRulename{
														Name: "DIGIT",
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

	abnfElement = &Rule{
		Name: "element",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "rulename",
							},
						},
					},
				},
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "group",
							},
						},
					},
				},
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "option",
							},
						},
					},
				},
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "char-val",
							},
						},
					},
				},
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "num-val",
							},
						},
					},
				},
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "prose-val",
							},
						},
					},
				},
			},
		},
	}

	abnfGroup = &Rule{
		Name: "group",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'('},
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "c-wsp",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "alternation",
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "c-wsp",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{')'},
							},
						},
					},
				},
			},
		},
	}

	abnfOption = &Rule{
		Name: "option",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'['},
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "c-wsp",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "alternation",
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemRulename{
								Name: "c-wsp",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{']'},
							},
						},
					},
				},
			},
		},
	}

	// Written as overrided by RFC 7405
	abnfCharVal = &Rule{
		Name: "char-val",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "case-insensitive-string",
							},
						},
					},
				}, {
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "case-sensitive-string",
							},
						},
					},
				},
			},
		},
	}

	abnfCaseInsensitiveString = &Rule{
		Name: "case-insensitive-string",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemOption{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemCharVal{
														Sensitive: false,
														Values:    []byte{'%', 'i'},
													},
												},
											},
										},
									},
								},
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "quoted-string",
							},
						},
					},
				},
			},
		},
	}

	abnfCaseSensitiveString = &Rule{
		Name: "case-sensitive-string",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'%', 's'},
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "quoted-string",
							},
						},
					},
				},
			},
		},
	}

	abnfQuotedString = &Rule{
		Name: "quoted-string",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "DQUOTE",
							},
						}, {
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemNumVal{
														Base:   "x",
														Status: StatRange,
														Elems:  []byte{0x20, 0x21},
													},
												},
											},
										}, {
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemNumVal{
														Base:   "x",
														Status: StatRange,
														Elems:  []byte{0x23, 0x7E},
													},
												},
											},
										},
									},
								},
							},
						}, {
							Min: 1,
							Max: 1,
							Element: ElemRulename{
								Name: "DQUOTE",
							},
						},
					},
				},
			},
		},
	}

	abnfNumVal = &Rule{
		Name: "num-val",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'%'},
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "bin-val",
													},
												},
											},
										},
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "dec-val",
													},
												},
											},
										},
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemRulename{
														Name: "hex-val",
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

	abnfBinVal = &Rule{
		Name: "bin-val",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'b'},
							},
						},
						{
							Min: 1,
							Max: inf,
							Element: ElemRulename{
								Name: "BIT",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemOption{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: inf,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 1,
																			Max: 1,
																			Element: ElemCharVal{
																				Sensitive: false,
																				Values:    []byte{'.'},
																			},
																		},
																		{
																			Min: 1,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "BIT",
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
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 1,
																			Max: 1,
																			Element: ElemCharVal{
																				Sensitive: false,
																				Values:    []byte{'-'},
																			},
																		},
																		{
																			Min: 1,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "BIT",
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

	abnfDecVal = &Rule{
		Name: "dec-val",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'d'},
							},
						},
						{
							Min: 1,
							Max: inf,
							Element: ElemRulename{
								Name: "DIGIT",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemOption{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: inf,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 1,
																			Max: 1,
																			Element: ElemCharVal{
																				Sensitive: false,
																				Values:    []byte{'.'},
																			},
																		},
																		{
																			Min: 1,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "DIGIT",
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
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 1,
																			Max: 1,
																			Element: ElemCharVal{
																				Sensitive: false,
																				Values:    []byte{'-'},
																			},
																		},
																		{
																			Min: 1,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "DIGIT",
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

	abnfHexVal = &Rule{
		Name: "hex-val",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'x'},
							},
						},
						{
							Min: 1,
							Max: inf,
							Element: ElemRulename{
								Name: "HEXDIG",
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemOption{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: inf,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 1,
																			Max: 1,
																			Element: ElemCharVal{
																				Sensitive: false,
																				Values:    []byte{'.'},
																			},
																		},
																		{
																			Min: 1,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "HEXDIG",
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
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemGroup{
														Alternation: Alternation{
															Concatenations: []Concatenation{
																{
																	Repetitions: []Repetition{
																		{
																			Min: 1,
																			Max: 1,
																			Element: ElemCharVal{
																				Sensitive: false,
																				Values:    []byte{'-'},
																			},
																		},
																		{
																			Min: 1,
																			Max: inf,
																			Element: ElemRulename{
																				Name: "HEXDIG",
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

	abnfProseVal = &Rule{
		Name: "prose-val",
		Alternation: Alternation{
			Concatenations: []Concatenation{
				{
					Repetitions: []Repetition{
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'<'},
							},
						},
						{
							Min: 0,
							Max: inf,
							Element: ElemGroup{
								Alternation: Alternation{
									Concatenations: []Concatenation{
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemNumVal{
														Base:   "x",
														Status: StatRange,
														Elems:  []byte{0x20, 0x3D},
													},
												},
											},
										},
										{
											Repetitions: []Repetition{
												{
													Min: 1,
													Max: 1,
													Element: ElemNumVal{
														Base:   "x",
														Status: StatRange,
														Elems:  []byte{0x3F, 0x7E},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							Min: 1,
							Max: 1,
							Element: ElemCharVal{
								Sensitive: false,
								Values:    []byte{'>'},
							},
						},
					},
				},
			},
		},
	}
)
