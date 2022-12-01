package goabnf

// // ParseABNF parses a given ABNF input, and returns its
// // corresponding grammar.
// func ParseABNF(input []byte) (*Grammar, error) {
// 	// Create worker pool
// 	pool := pool{
// 		workers: []*worker{
// 			// Initial worker
// 			{
// 				path:  "rulelist", // root of an ABNF grammar
// 				index: 0,          // start of the input
// 			},
// 		},
// 	}

// 	// Parse each rule
// 	// var rulelist []rule
// 	for wrk := pool.Pop(); wrk != nil; wrk = nil {
// 		for i, concat := range rulelist.alternation.concatenations {
// 			for j, rep := range concat.repetitions {
// 				for i := min; i < max || max == inf; i++
// 			}
// 		}
// 	}

// 	return nil, nil
// }

type worker struct {
	// path indicate the path used by the worker to get here.
	// It is formatted using an index when necessary.
	// It is splitted using a dot.
	path string

	// index is the index of the char that is consumed in the
	// input.
	// 0 is the first char of it , 1 is the next, and so on.
	index int
}

type pool struct {
	workers []*worker
}

func (p *pool) Add(worker *worker) {
	if worker == nil {
		panic("nil worker to add into the pool")
	}
	p.workers = append(p.workers, worker)
}

func (p *pool) Pop() *worker {
	l := len(p.workers)
	if l == 0 {
		return nil
	}
	w := p.workers[l-1]
	p.workers = p.workers[:l-1]
	return w
}
