package ldpcDecoding

type Parameters struct {
	n    int
	m    int
	wc   int
	wr   int
	seed int
}

type Mode uint

type Config struct {
	PowMode Mode
}

type difficulty struct {
	level        int
	n            int
	wc           int
	wr           int
	decisionFrom int
	decisionTo   int
	decisionStep int
	_            float32
	miningProb   float64
}

var Table = []difficulty{
	{0, 32, 3, 4, 10, 22, 2, 0.329111, 3.077970e-05},
	{1, 32, 3, 4, 10, 22, 2, 0.329111, 3.077970e-05},
	{2, 32, 3, 4, 10, 16, 2, 0.329111, 2.023220e-05},
	{3, 32, 3, 4, 16, 16, 1, 0.329111, 9.684650e-06},
	{4, 32, 3, 4, 14, 14, 1, 0.329111, 6.784080e-06},
	{5, 36, 3, 4, 12, 24, 2, 0.329111, 4.830240e-06},
	{6, 36, 3, 4, 12, 18, 2, 0.369449, 3.125970e-06},
	{7, 32, 3, 4, 12, 12, 1, 0.369449, 2.862890e-06},
	{8, 44, 3, 4, 14, 30, 2, 0.369449, 1.637790e-06},
	{9, 36, 3, 4, 18, 18, 1, 0.369449, 1.421700e-06},
	{10, 36, 3, 4, 16, 16, 1, 0.369449, 1.051350e-06},
}
