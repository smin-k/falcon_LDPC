package vct

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"falcon_vct/falcon"
	"time"
)

const log1024 uint = 10

type set_probablity struct {
	probablity uint8
	norm_bound uint32
}

// Percentage expected to pass the VCT / norm bound
var Prob = []set_probablity{
	{5, 55085531},  // ~5%
	{10, 55744816}, // ~10%
	{15, 56189632}, // ~15%
	{20, 56543158}, // ~20%
	{25, 56846452}, // ~25%
	{30, 57118819}, // ~30%
}

type Nodes struct {
	id       string
	pi       string
	norm     int
	VCT_res  bool
	vrfy_res string
	exe_time string
}

func norm_s(s1, s2 [1024]int16, logn uint) uint32 {
	n := 1 << logn
	s := uint32(0)

	for u := 0; u < n; u++ {
		var z int32

		z = int32(s1[u])
		s += uint32(z * z)

		z = int32(s2[u])
		s += uint32(z * z)
	}

	return s
}

func VCTtest(howmany int, message string, probability uint8, verbose bool) ([]int, time.Duration) {
	var msg []byte
	var VCT_res bool
	var verify_res string
	msg = []byte(message)
	nodeSet := make([]Nodes, howmany)
	winVCT := []int{}
	nthreshold := Prob[(probability/5)-1].norm_bound

	totalTime := time.Now()
	for i := 0; i < howmany; i++ {
		startTime := time.Now()
		mathrand.Seed(time.Now().Unix())
		seed := make([]byte, 64)
		rand.Read(seed)
		pk, sk, _ := falcon.GenerateKey(seed)

		sig, _ := sk.SignCompressed(msg)
		err := pk.Verify(sig, msg)

		if err == nil {
			verify_res = "success"
		} else {
			verify_res = "failed"
		}

		enc_sig := hex.EncodeToString(sig)

		sigCT, _ := sig.ConvertToCT()
		s2, _ := sigCT.S2Coefficients()
		h, _ := pk.Coefficients()

		c := falcon.HashToPointCoefficients(msg, sigCT.SaltVersion())
		s1, _ := falcon.S1Coefficients(h, c, s2)

		norm := norm_s(s1, s2, log1024)

		if norm < nthreshold {
			winVCT = append(winVCT, i)
			VCT_res = true
		} else {
			VCT_res = false
		}

		elapsedTime := time.Since(startTime)

		nodeSet[i] = Nodes{fmt.Sprint("node_", i), enc_sig, int(norm), VCT_res, verify_res, elapsedTime.String()}
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
