package ldpcDecoding

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/rand"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func BigIntToFloat(val *big.Int) float64 {
	// big int -> bit float -> float64
	bigFloat := new(big.Float).SetInt(val)
	floatVal, _ := bigFloat.Float64()

	return floatVal
}

func FloatToBigInt(val float64) *big.Int {
	// float64 -> bit float -> big int
	bigFloat := big.NewFloat(val)
	bigInt := new(big.Int)
	bigFloat.Int(bigInt)

	return bigInt
}

func funcF(x float64) float64 {
	if x >= BigInfinity {
		return 1.0 / BigInfinity
	} else if x <= (1.0 / BigInfinity) {
		return BigInfinity
	} else {
		return math.Log((math.Exp(x) + 1) / (math.Exp(x) - 1))
	}
}

func DifficultyToProb(difficulty *big.Int) float64 {
	//big Int -> 1/bigInt -> float64
	prob := 1 / BigIntToFloat(difficulty)
	return prob
}

func ProbToDifficulty(miningProb float64) *big.Int {
	// float64 -> 1/float64 -> big Int
	difficulty := FloatToBigInt(1 / miningProb)
	return difficulty
}

func SearchLevel(difficulty *big.Int) int {
	var currentProb = DifficultyToProb(difficulty)
	var level int

	distance := 1.0
	for i := range Table {
		if math.Abs(currentProb-Table[i].miningProb) <= distance {
			level = Table[i].level
			distance = math.Abs(currentProb - Table[i].miningProb)
		} else {
			break
		}
	}

	return level
}

func infinityTest(x float64) float64 {
	if x >= Inf {
		return Inf
	} else if x <= -Inf {
		return -Inf
	} else {
		return x
	}
}

func generateSeed(phv [32]byte) int {
	sum := 0
	for i := 0; i < len(phv); i++ {
		sum += int(phv[i])
	}
	return sum
}

// TextHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
func TextHash(data []byte) ([]byte, string) {
	hash, msg := TextAndHash(data)
	return hash, msg
}

// TextAndHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
func TextAndHash(data []byte) ([]byte, string) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), string(data))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	return hasher.Sum(nil), msg
}

func setParameters(header *types.Header) (Parameters, int) {
	level := SearchLevel(header.Difficulty)

	parameters := Parameters{
		n:  Table[level].n,
		wc: Table[level].wc,
		wr: Table[level].wr,
	}
	parameters.m = int(parameters.n * parameters.wc / parameters.wr)
	parameters.seed = generateSeed(header.ParentHash)

	return parameters, level
}

func generateRandomNonce() uint64 {
	seed, _ := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	source := rand.New(rand.NewSource(seed.Int64()))

	return uint64(source.Int63())
}

//generateH generate H matrix using parameters
//generateH Cannot be sure rand is same with original implementation of C++
func generateH(parameters Parameters) [][]int {
	var H [][]int
	var hSeed int64
	var colOrder []int

	hSeed = int64(parameters.seed)
	k := parameters.m / parameters.wc

	H = make([][]int, parameters.m)
	for i := range H {
		H[i] = make([]int, parameters.n)
	}

	for i := 0; i < k; i++ {
		for j := i * parameters.wr; j < (i+1)*parameters.wr; j++ {
			H[i][j] = 1
		}
	}

	for i := 1; i < parameters.wc; i++ {
		colOrder = nil
		for j := 0; j < parameters.n; j++ {
			colOrder = append(colOrder, j)
		}

		rand.Seed(hSeed)
		rand.Shuffle(len(colOrder), func(i, j int) {
			colOrder[i], colOrder[j] = colOrder[j], colOrder[i]
		})
		hSeed--

		for j := 0; j < parameters.n; j++ {
			index := (colOrder[j]/parameters.wr + k*i)
			H[index][j] = 1
		}
	}

	return H
}

func generateQ(parameters Parameters, H [][]int) ([][]int, [][]int) {
	colInRow := make([][]int, parameters.wr)
	for i := 0; i < parameters.wr; i++ {
		colInRow[i] = make([]int, parameters.m)
	}

	rowInCol := make([][]int, parameters.wc)
	for i := 0; i < parameters.wc; i++ {
		rowInCol[i] = make([]int, parameters.n)
	}

	rowIndex := 0
	colIndex := 0

	for i := 0; i < parameters.m; i++ {
		for j := 0; j < parameters.n; j++ {
			if H[i][j] == 1 {
				colInRow[colIndex%parameters.wr][i] = j
				colIndex++

				rowInCol[rowIndex/parameters.n][j] = i
				rowIndex++
			}
		}
	}

	return colInRow, rowInCol
}

func generateHv(parameters Parameters, encryptedHeaderWithNonce []byte) []int {
	hashVector := make([]int, parameters.n)

	/*
		if parameters.n <= 256 {
			tmpHashVector = sha256.Sum256(headerWithNonce)
		} else {
			/*
				This section is for a case in which the size of a hash vector is larger than 256.
				This section will be implemented soon.
		}
			transform the constructed hexadecimal array into an binary array
			ex) FE01 => 11111110000 0001
	*/

	for i := 0; i < parameters.n/8; i++ {
		decimal := int(encryptedHeaderWithNonce[i])
		for j := 7; j >= 0; j-- {
			hashVector[j+8*(i)] = decimal % 2
			decimal /= 2
		}
	}

	//outputWord := hashVector[:parameters.n]
	return hashVector
}

func OptimizedDecoding(parameters Parameters, hashVector []int, H, rowInCol, colInRow [][]int) ([]int, []int, [][]float64) {
	outputWord := make([]int, parameters.n)
	LRqtl := make([][]float64, parameters.n)
	LRrtl := make([][]float64, parameters.n)
	LRft := make([]float64, parameters.n)

	for i := 0; i < parameters.n; i++ {
		LRqtl[i] = make([]float64, parameters.m)
		LRrtl[i] = make([]float64, parameters.m)
		LRft[i] = math.Log((1-crossErr)/crossErr) * float64((hashVector[i]*2 - 1))
	}
	LRpt := make([]float64, parameters.n)

	for ind := 1; ind <= maxIter; ind++ {
		for t := 0; t < parameters.n; t++ {
			temp3 := 0.0

			for mp := 0; mp < parameters.wc; mp++ {
				temp3 = infinityTest(temp3 + LRrtl[t][rowInCol[mp][t]])
			}
			for m := 0; m < parameters.wc; m++ {
				temp4 := temp3
				temp4 = infinityTest(temp4 - LRrtl[t][rowInCol[m][t]])
				LRqtl[t][rowInCol[m][t]] = infinityTest(LRft[t] + temp4)
			}
		}

		for k := 0; k < parameters.wr; k++ {
			for l := 0; l < parameters.wr; l++ {
				temp3 := 0.0
				sign := 1.0
				tempSign := 0.0
				for m := 0; m < parameters.wr; m++ {
					if m != l {
						temp3 = temp3 + funcF(math.Abs(LRqtl[colInRow[m][k]][k]))
						if LRqtl[colInRow[m][k]][k] > 0.0 {
							tempSign = 1.0
						} else {
							tempSign = -1.0
						}
						sign = sign * tempSign
					}
				}
				magnitude := funcF(temp3)
				LRrtl[colInRow[l][k]][k] = infinityTest(sign * magnitude)
			}
		}

		for t := 0; t < parameters.n; t++ {
			LRpt[t] = infinityTest(LRft[t])
			for k := 0; k < parameters.wc; k++ {
				LRpt[t] += LRrtl[t][rowInCol[k][t]]
				LRpt[t] = infinityTest(LRpt[t])
			}

			if LRpt[t] >= 0 {
				outputWord[t] = 1
			} else {
				outputWord[t] = 0
			}
		}
	}

	return hashVector, outputWord, LRrtl
}

func RunOptimizedConcurrencyLDPC(header *types.Header, hash []byte) (bool, []int, []int, uint64, []byte) {
	//Need to set difficulty before running LDPC
	// Number of goroutines : 500, Number of attempts : 50000 Not bad

	var LDPCNonce uint64
	var hashVector []int
	var outputWord []int
	var digest []byte
	var flag bool

	parameters, _ := setParameters(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	for i := 0; i < 64; i++ {
		var goRoutineHashVector []int
		var goRoutineOutputWord []int
		goRoutineNonce := generateRandomNonce()
		seed := make([]byte, 40)
		copy(seed, hash)
		binary.LittleEndian.PutUint64(seed[32:], goRoutineNonce)
		seed = crypto.Keccak512(seed)

		goRoutineHashVector = generateHv(parameters, seed)
		goRoutineHashVector, goRoutineOutputWord, _ = OptimizedDecoding(parameters, goRoutineHashVector, H, rowInCol, colInRow)
		flag = MakeDecision(header, colInRow, goRoutineOutputWord)

		if flag {
			hashVector = goRoutineHashVector
			outputWord = goRoutineOutputWord
			LDPCNonce = goRoutineNonce
			digest = seed
			break
		} else {
			hashVector = goRoutineHashVector
		}
	}
	return flag, hashVector, outputWord, LDPCNonce, digest
}

//MakeDecision check outputWord is valid or not using colInRow
func MakeDecision(header *types.Header, colInRow [][]int, outputWord []int) bool {
	parameters, difficultyLevel := setParameters(header)
	for i := 0; i < parameters.m; i++ {
		sum := 0
		for j := 0; j < parameters.wr; j++ {
			//	fmt.Printf("i : %d, j : %d, m : %d, wr : %d \n", i, j, m, wr)
			sum = sum + outputWord[colInRow[j][i]]
		}
		if sum%2 == 1 {
			return false
		}
	}

	var numOfOnes int
	for _, val := range outputWord {
		numOfOnes += val
	}

	if numOfOnes >= Table[difficultyLevel].decisionFrom &&
		numOfOnes <= Table[difficultyLevel].decisionTo &&
		numOfOnes%Table[difficultyLevel].decisionStep == 0 {
		return true
	}

	return false
}
