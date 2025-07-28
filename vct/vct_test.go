package vct

import (
	"fmt"
	"time"
	"reflect"
	"testing"
)

type Nodes struct {
	id       string
	pi       string
	norm     int
	VCT_res  bool
	vrfy_res string
	exe_time string
}

func VCTtest(howmany int, message string, probability uint8, verbose bool) ([]int, time.Duration) {
	var msg []byte
	msg = []byte(message)
	nodeSet := make([]Nodes, howmany)
	winVCT := []int{}
	nthreshold := Prob[(probability/5)-1].norm_bound

	totalTime := time.Now()
	for i := 0; i < howmany; i++ {
		nodeSet[i] = PerformFalconVCT(i, msg, nthreshold)
		if nodeSet[i].VCT_res {
			winVCT = append(winVCT, i)
		}
	}
	totalElapsedTime := time.Since(totalTime)
	avgElapsedTime := totalElapsedTime / time.Duration(howmany)

	fmt.Println()

	if verbose {
		for i := 0; i < howmany; i++ {
			var temp int = len(nodeSet[i].pi)
			fmt.Println("------------------------------------------------------------------------------------------------------------------------")
			fmt.Println("id : ", nodeSet[i].id)
			fmt.Println("norm : ", nodeSet[i].norm)
			fmt.Println("VCT result : ", nodeSet[i].VCT_res)
			fmt.Println("proof : ", nodeSet[i].pi[:16], "......", nodeSet[i].pi[temp-9:])
			fmt.Println("verify : ", nodeSet[i].vrfy_res)
			fmt.Println("elapsed_time : ", nodeSet[i].exe_time)
			fmt.Println("------------------------------------------------------------------------------------------------------------------------")
		}
	}
	return winVCT, avgElapsedTime
}

// 같은 seed / 메시지 / 확률 -> 동일 결과
func TestDeterministicSingle(t *testing.T) {
	msg := []byte("deterministic")
	nth := Prob[1].norm_bound // 10%

	seed := makeSeed(42)
	n1 := PerformFalconVCT(0, msg, nth, seed)
	n2 := PerformFalconVCT(0, msg, nth, seed)

	// 실행시간 문자열만 제거 후 비교
	n1.exe_time, n2.exe_time = "", ""
	if !reflect.DeepEqual(n1, n2) {
		t.Fatalf("non-deterministic: %+v != %+v", n1, n2)
	}
}

func TestDeterministicBatch(t *testing.T) {
	howmany := 5
	seeds := make([][]byte, howmany)
	for i := 0; i < howmany; i++ {
		seeds[i] = makeSeed(uint64(100 + i))
	}

	win1, _ := VCTtest(howmany, "batch-test", 10, false, seeds)
	win2, _ := VCTtest(howmany, "batch-test", 10, false, seeds)

	if !reflect.DeepEqual(win1, win2) {
		t.Fatalf("winner set differs: %v vs %v", win1, win2)
	}
}
