package ldpcDecoding

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/core/types"
)

func RunLDPC(nodeset []int) {
	header := new(types.Header)
	header.Difficulty = ProbToDifficulty(Table[5].miningProb)
	//spew.Dump(header) // Print header

	// params, _ := setParameters(header)
	// fmt.Printf("%+v\n\n", params)

OuterFor:
	for i := 1; i < 3000000; i++ {
		for _, j := range nodeset {
			temp := fmt.Sprintf("node%d", j)
			hash, _ := TextHash([]byte(temp))
			// for_sync_hash := "in order for all test nodes to use the same hash"
			// hash, _ := TextHash([]byte(for_sync_hash))

			flag, hashVector, outputWord, LDPCNonce, digest := RunOptimizedConcurrencyLDPC(header, hash)

			if flag {
				fmt.Printf("node%d found vector!      (try : %d)\n", j, i)
				fmt.Printf("node%d's hash vector : %v\n", j, hashVector)
				fmt.Printf("node%d's outputWord : %v\n", j, outputWord)
				fmt.Printf("node%d's nonce : %v\n", j, LDPCNonce)
				fmt.Printf("node%d's seed : %v\n\n", j, digest)
				break OuterFor
			}
		}
		// fmt.Println()
	}
}

func RunLDPCdecoding() {
	header := new(types.Header)
	header.Difficulty = ProbToDifficulty(Table[1].miningProb)
	spew.Dump(header) // Print header

	params, _ := setParameters(header)
	fmt.Printf("%+v\n\n", params)

	for i := 0; i < 300000; i++ {
		message := fmt.Sprintf("Try number %d", i)
		hash, msg := TextHash([]byte(message))
		fmt.Println(msg)
		fmt.Println(hash)

		flag, hashVector, outputWord, LDPCNonce, digest := RunOptimizedConcurrencyLDPC(header, hash)
		fmt.Printf("flag : %v\n", flag)
		fmt.Printf("Hash vector : %v\n", hashVector)
		fmt.Printf("outputWord : %v\n", outputWord)
		fmt.Printf("LDPCNonce : %v\n", LDPCNonce)
		fmt.Printf("digest : %v\n", digest)

		if flag {
			break
		}
	}
}
