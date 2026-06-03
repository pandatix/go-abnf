# Fuzzing targets

Each target couples the coverage-guided engine to the grammar differently. The
diagrams below render natively on GitHub.

**Legend** -- 🟦 engine · 🟪 go-abnf method · ⬜ data/input · 🟧 oracle (assertion) · 🟥 bug class found · 🟩 pass

---

## `FuzzFunction` -- baseline (seed-int generator)

The engine mutates a `seed int64`; a seed has almost no locality (a small edit
jumps randomly around production space) and only ever yields *valid* inputs.
Kept as a contrast to the tape-driven targets.

```mermaid
flowchart TD
    E["Fuzzing engine<br/>mutates a seed int64"]
    G["g.Generate(seed, a)"]
    P["valid production"]
    F["Function(b)"]
    N["weak gradient: a seed int has little<br/>locality; valid-only; no explicit oracle"]
    E -->|"seed"| G --> P --> F
    F -.->|"coverage feedback"| E
    G -.- N
    classDef engine fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a;
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef note fill:#fff7ed,stroke:#fdba74,color:#7c2d12;
    class E engine
    class G method
    class P,F artifact
    class N note
```

---

## `FuzzValidAccepted` -- `Generate`: structure-aware valid inputs

Every tape maps to a grammar-valid production, so the engine explores the
*grammar* instead of bouncing off the target's first syntax check, and deep
target code is always reached. **Oracle: the target must accept → finds false
rejections.**

```mermaid
flowchart TD
    E["Fuzzing engine<br/>mutates the tape (bytes)"]
    G["gen.Generate(tape)<br/>walk transition graph"]
    P["ALWAYS-valid<br/>production"]
    SC{"IsValid?<br/>self-check"}
    F{"Function<br/>accepts?"}
    BUG1["go-abnf generator bug"]
    BUG["FALSE REJECTION"]
    OK["pass"]
    E -->|"tape"| G --> P --> SC
    SC -->|"no"| BUG1
    SC -->|"yes"| F
    F -->|"no"| BUG
    F -->|"yes"| OK
    F -.->|"coverage feedback"| E
    classDef engine fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a;
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef oracle fill:#ffedd5,stroke:#f97316,color:#7c2d12;
    classDef bug fill:#fee2e2,stroke:#ef4444,color:#7f1d1d;
    classDef pass fill:#dcfce7,stroke:#16a34a,color:#14532d;
    class E engine
    class G method
    class P artifact
    class SC,F oracle
    class BUG,BUG1 bug
    class OK pass
```

---

## `FuzzValidAcceptedStable` -- `WithStableAddressing` codec

Addresses the tape by decision number (fixed slots) instead of a moving cursor,
so one byte edit perturbs one decision rather than reframing all later ones.
A win on concatenation / fixed-repetition grammars; can hurt repetition-heavy
ones -- so it is an opt-in to A/B against the default codec.

```mermaid
flowchart TD
    G["gen.Generate(tape)"]
    subgraph CUR["default codec: moving cursor"]
      direction LR
      C1["one tape byte edited"] --> C2["consumed-byte count shifts"] --> C3["ALL later decisions reframed<br/>= large jump"]
    end
    subgraph STB["WithStableAddressing: fixed slots"]
      direction LR
      S1["one tape byte edited"] --> S2["lands in one fixed slot"] --> S3["ONE decision perturbed<br/>= local change"]
    end
    N["Win on fixed-structure grammars.<br/>Can be worse on repetition-heavy grammars -- A/B it."]
    G --> CUR
    G --> STB
    STB -.- N
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef good fill:#dcfce7,stroke:#16a34a,color:#14532d;
    classDef bad fill:#fee2e2,stroke:#ef4444,color:#7f1d1d;
    classDef note fill:#fff7ed,stroke:#fdba74,color:#7c2d12;
    class G method
    class C1,C2,S1,S2 artifact
    class S3 good
    class C3 bad
    class N note
```

---

## `FuzzNearMissRejected` -- `NearMiss`: structure-aware invalid inputs

Minimal off-grammar perturbations of a valid production, each verified against
the grammar to be genuinely rejected and carrying a label. They reach the error
paths a valid-only generator can never hit. **Oracle: the target must reject →
finds over-acceptance** (a parser swallowing malformed input).

```mermaid
flowchart TD
    E["engine mutates tape"]
    subgraph NM["gen.NearMiss(tape)"]
      direction TB
      B["generate valid base"]
      PERT["apply ONE minimal perturbation:<br/>boundary / truncate / trailing /<br/>ExpectedNext-forbidden octet"]
      V{"grammar<br/>rejects?"}
      LBL["labeled near-miss"]
      B --> PERT --> V
      V -->|"no (still valid)"| PERT
      V -->|"yes"| LBL
    end
    R{"Function<br/>rejects?"}
    BUG["OVER-ACCEPTANCE"]
    OK["pass"]
    E -->|"tape"| NM
    LBL --> R
    R -->|"no"| BUG
    R -->|"yes"| OK
    R -.->|"coverage feedback"| E
    classDef engine fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a;
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef oracle fill:#ffedd5,stroke:#f97316,color:#7c2d12;
    classDef bug fill:#fee2e2,stroke:#ef4444,color:#7f1d1d;
    classDef pass fill:#dcfce7,stroke:#16a34a,color:#14532d;
    class E engine
    class B,PERT,LBL method
    class V,R oracle
    class BUG bug
    class OK pass
```

---

## `FuzzExpectedNextErrorPosition` -- `ExpectedNext`: error-position testing

`ExpectedNext` returns the octets the grammar allows after a prefix. Appending
one it forbids yields a guaranteed-invalid input whose first error sits at a
*known* offset. **Oracle: the target must reject -- and, if it reports an error
position, that position must be the injection offset.**

```mermaid
flowchart TD
    G["gen.Generate(tape)"]
    P["valid production"]
    CUT["prefix = production up to offset N"]
    EN["gen.ExpectedNext(prefix)"]
    SET["allowed octets at offset N"]
    PICK["pick an octet NOT allowed"]
    BAD["prefix + forbidden octet<br/>invalid, first error at offset N"]
    R{"Function rejects?<br/>(optional: fails AT N?)"}
    BUG["accepts illegal octet<br/>or wrong error position"]
    OK["pass"]
    G --> P --> CUT --> EN --> SET --> PICK --> BAD --> R
    R -->|"no"| BUG
    R -->|"yes"| OK
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef oracle fill:#ffedd5,stroke:#f97316,color:#7c2d12;
    classDef bug fill:#fee2e2,stroke:#ef4444,color:#7f1d1d;
    classDef pass fill:#dcfce7,stroke:#16a34a,color:#14532d;
    class G,EN method
    class P,CUT,SET,PICK,BAD artifact
    class R oracle
    class BUG bug
    class OK pass
```

---

## `FuzzDifferentialBothDirections` -- combination

One tape drives both directions: the target must accept the valid production
**and** reject the near-miss derived from the same entropy. Catches false
rejections and over-acceptance together, maximizing signal per execution.

```mermaid
flowchart TD
    E["engine mutates tape"]
    T["tape"]
    G["gen.Generate(tape)"]
    NM["gen.NearMiss(tape)"]
    PV["valid production"]
    NV["labeled near-miss"]
    POS{"Function<br/>accepts valid?"}
    NEG{"Function<br/>rejects invalid?"}
    B1["FALSE REJECTION"]
    B2["OVER-ACCEPTANCE"]
    OK["pass both directions"]
    E --> T
    T --> G --> PV --> POS
    T --> NM --> NV --> NEG
    POS -->|"no"| B1
    POS -->|"yes"| OK
    NEG -->|"no"| B2
    NEG -->|"yes"| OK
    classDef engine fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a;
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef oracle fill:#ffedd5,stroke:#f97316,color:#7c2d12;
    classDef bug fill:#fee2e2,stroke:#ef4444,color:#7f1d1d;
    classDef pass fill:#dcfce7,stroke:#16a34a,color:#14532d;
    class E engine
    class T,PV,NV artifact
    class G,NM method
    class POS,NEG oracle
    class B1,B2 bug
    class OK pass
```

---

## `FuzzAST` -- `ASTGenerator`: recursive grammars

The transition-graph generator is a finite automaton, so it rejects recursive
rules as cyclic. `ASTGenerator` instead generates by recursive descent over the
grammar AST, so a rule reached at many depths -- nested objects, balanced
delimiters, expression grammars -- is fully supported. Every tape still maps to
an always-valid production; termination is guaranteed by precomputing each
rule's minimum expansion cost and steering toward the cheapest finish once a
depth/length budget trips, so even left recursion bottoms out. **Oracle: the
target must accept → finds false rejections, especially the depth-triggered ones
byte fuzzing rarely reaches.**

```mermaid
flowchart TD
    E["Fuzzing enginemutates the tape (bytes)"]
    G["gen.Generate(tape) recursive descent over AST"]
    P["ALWAYS-valid production (possibly deeply nested)"]
    SC{"IsValid? self-check"}
    F{"Functionaccepts?"}
    BUG1["go-abnf generator bug"]
    BUG["FALSE REJECTION(often depth-triggered)"]
    OK["pass"]
    N["RECURSIVE rule reached at many depths -- graph methods reject it as cyclic. Terminates by construction via min-cost steering (WithMaxDepth / WithMaxLen)."]
    E -->|"tape"| G --> P --> SC
    SC -->|"no"| BUG1
    SC -->|"yes"| F
    F -->|"no"| BUG
    F -->|"yes"| OK
    F -.->|"coverage feedback"| E
    G -.- N
    classDef engine fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a;
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef oracle fill:#ffedd5,stroke:#f97316,color:#7c2d12;
    classDef bug fill:#fee2e2,stroke:#ef4444,color:#7f1d1d;
    classDef pass fill:#dcfce7,stroke:#16a34a,color:#14532d;
    classDef note fill:#fff7ed,stroke:#fdba74,color:#7c2d12;
    class E engine
    class G method
    class P artifact
    class SC,F oracle
    class BUG,BUG1 bug
    class OK pass
    class N note
```

## Comparison

| Target | Finds | Pros | Cons | Requirements | Limitations |
|---|---|---|---|---|---|
| **`FuzzFunction`** (seed) | crashes on valid input only | • simplest setup<br/>• no transition graph<br/>• the only route when the rule is **recursive** | • weak gradient (a seed int has poor locality)<br/>• valid-only<br/>• no differential oracle by default | • a grammar<br/>• legacy `Generate` (`WithRepMax`, `WithThreshold`) | • won't surface false-rejection / over-acceptance without added assertions<br/>• shallow coverage exploration |
| **`FuzzValidAccepted`** (`Generate`) | false rejections | • structure-aware → explores the grammar<br/>• always clears the validity gate, so deep code is reached<br/>• self-check flags go-abnf generator bugs | • valid-only → no error paths<br/>• many no-op mutations waste cycles<br/>• gradient hurt by frame-shift on loop-heavy grammars | † + a `Function` **accept** signal | ‡ + cannot find over-acceptance |
| **`FuzzValidAcceptedStable`** | false rejections | • smoother gradient on fixed-structure grammars (one byte = one decision) | • can **reduce** locality on repetition-heavy grammars<br/>• consumes the tape less densely | † + `WithStableAddressing` | ‡ + benefit is grammar-shape-dependent → must A/B against the default codec |
| **`FuzzNearMissRejected`** (`NearMiss`) | over-acceptance (security-relevant) | • reaches the error paths a valid generator can't<br/>• every output verified-invalid → sound oracle<br/>• labeled for diagnostics<br/>• high yield | • runs `IsValid` per candidate (CPU cost)<br/>• occasional `ok=false` (that exec asserts nothing)<br/>• single-step perturbations | † + a `Function` **reject** signal | ‡ + only *near* misses (one edit) → misses deeply-malformed inputs |
| **`FuzzExpectedNextErrorPosition`** (`ExpectedNext`) | accepts-illegal-octet; wrong error offset | • guaranteed-invalid by construction (no verify needed)<br/>• tests error **position**, not just accept/reject<br/>• sharpest diagnostics | • the position check needs a position-reporting target (otherwise it just overlaps `NearMiss`) | † + ideally a target that returns an **error offset** | ‡ + `ExpectedNext` returns `ok=false` on enormous multi-byte ranges<br/>• single-octet boundary violations only |
| **`FuzzDifferentialBothDirections`** | false rejections **and** over-acceptance | • maximal signal per exec<br/>• tests the full accept/reject equivalence<br/>• a single corpus covers both | • heaviest per exec (`Generate` + `NearMiss` + 2× `IsValid` + 2× `Function`)<br/>• a failure needs direction disambiguation (the label helps) | † + **both** accept and reject signals | ‡ + union of the two single-direction limits |
| **`FuzzAST`** (`ASTGenerator`) | false rejections (often recursion/depth-triggered) | • the only structure-aware route for **recursive** rules (graph methods reject them as cyclic)<br/>• always-valid **and** terminates by construction -- min-cost steering bounds even left recursion (no stack blow-up)<br/>• reaches deep nesting / rules used at many depths that byte fuzzing rarely hits<br/>• self-check flags generator bugs | • valid-only → no error paths<br/>• cost-steering favors short productions → rare/deep branches under-sampled near the budget (sampling bias)<br/>• no `NearMiss` / `ExpectedNext` counterpart (no automaton) | § start and all reachable rules **defined + productive**; `NewASTGenerator` budgets (`WithMaxDepth`, `WithMaxLen`, `WithMaxRepeat`) -- **no** transition graph | ‡ + valid-only (no over-acceptance)<br/>• depth/size bounded by the budgets (won't explore past the ceiling) |

**†  Shared requirements** (all transition-graph targets): a fully-expanded, acyclic graph -- `TransitionGraph(rule, WithDeflateRules(true))`, where rule **recursion is rejected** but `*` repetition is fine -- plus generator budgets (`WithMaxLength`, `WithMaxReps`), and `WithMaxNodes` when the grammar itself is untrusted input.

**‡  Shared limitations**: *syntactic coverage only* -- the ABNF is a **superset** of the spec, so prose constraints (value bounds, context-sensitivity, `prose-val` holes) are not tested; and the tape indirection yields a **weaker coverage gradient** than native byte fuzzing (no-op mutations, frame-shift).

**§  `ASTGenerator` requirements**: it works directly on the AST, so it needs **no** transition graph and handles recursion natively; it only requires that every rule reachable from the start be defined and productive (otherwise `NewASTGenerator` errors), plus the depth/length/repeat budgets. The `‡` *syntactic-only* limitation still applies; the *tape-gradient* one applies too, with the added sampling bias noted in its row.

### Recommended combination

Run **`FuzzValidAccepted` + `FuzzNearMissRejected`** (or the single **`FuzzDifferentialBothDirections`**) as the core -- together they cover both false-rejection and over-acceptance. Add **`FuzzExpectedNextErrorPosition`** when the target reports error offsets. For **recursive** grammars -- which the graph methods reject as cyclic -- use **`FuzzValidList`** (`ASTGenerator`) for the valid-acceptance direction; it is tape-driven and bounded by construction, a strict improvement over the legacy seed generator for the recursive case (over-acceptance there still has no structure-aware tool -- that would need a near-miss layer over the AST generator). Keep **`FuzzFunction`** as a cheap smoke test.

The common-case routing (◇ = a question about your rule/target, 🟩 = the primary target for that branch, 🟪 = optional add-on):

```mermaid
flowchart TD
    START["Pick targets for an ABNF rule"]
    Q1{"Rule recursive? (TransitionGraph returns ErrCyclicRule)"}
    REC["FuzzValidList - ASTGenerator(valid-acceptance direction)"]
    RECNOTE["over-acceptance: no structure-aware tool yet for recursive rules"]
    CORE["CORE - FuzzDifferentialBothDirections = FuzzValidAccepted + FuzzNearMissRejected"]
    Q2{"Target returns an error offset?"}
    EN["add FuzzExpectedNextErrorPosition"]
    Q3{"Fixed-structure grammar? (concatenations, few '*' reps)"}
    STB["A/B FuzzValidAcceptedStable vs the default codec"]
    SMOKE["always cheap: keep FuzzFunction as a smoke test"]
    START --> Q1
    Q1 -->|"yes"| REC
    Q1 -->|"no"| CORE
    REC -.- RECNOTE
    REC --> SMOKE
    CORE --> Q2
    Q2 -->|"yes"| EN --> Q3
    Q2 -->|"no"| Q3
    Q3 -->|"yes"| STB --> SMOKE
    Q3 -->|"no"| SMOKE
    classDef artifact fill:#f3f4f6,stroke:#9ca3af,color:#111827;
    classDef decision fill:#f1f5f9,stroke:#64748b,color:#0f172a;
    classDef method fill:#ede9fe,stroke:#8b5cf6,color:#4c1d95;
    classDef note fill:#fff7ed,stroke:#fdba74,color:#7c2d12;
    classDef pass fill:#dcfce7,stroke:#16a34a,color:#14532d;
    class START artifact
    class Q1,Q2,Q3 decision
    class CORE,REC pass
    class EN,STB,SMOKE method
    class RECNOTE note
```

In short: recursion decides the engine (AST generator vs transition graph); within the transition-graph branch the differential is the default core, error-offset reporting adds the position oracle, and fixed-structure grammars are worth A/B-testing the stable codec. `FuzzFunction` stays as a cheap smoke test in every case.
