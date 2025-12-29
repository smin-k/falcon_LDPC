package main

import (
	"falcon_vct/eccpow"
	"falcon_vct/vct"
	"fmt"
	"os/exec"
)

func main() {
	const number_of_test_nodes int = 100
	var message string = "PREVIOUS BLOCK HEADER"
	var vct_or_not = 1

	if vct_or_not == 1 {
		var probability uint8 = 10

		var temp_for_prob = 0

		for i := 0; i < 1000; i++ {
			winVCT, avgTime := vct.VCTtest(number_of_test_nodes, message, probability, true)
			fmt.Println("nodes who passed VCT : ", winVCT)
			fmt.Println("average execute time : ", avgTime)
			fmt.Printf("percentage : %.1f %%\n\n", (float32(len(winVCT))/float32(number_of_test_nodes))*100)
			temp_for_prob += len(winVCT)
			fmt.Println("cumulate : ", temp_for_prob)

			// Passed Nodes now run LDPC Decoding algorithm
			fmt.Printf("Now we will start LDPC Decoding for ECCPOW.\n\n")
			ldpcDecoding.RunLDPC(winVCT)

			cmd := exec.Command("python", "snapshot.py")
			err := cmd.Run()
			if err != nil {
				fmt.Println(err.Error())
			}

		}
	}

	if vct_or_not == 0 {
		test_nodes := []int{}
		for k := 0; k < number_of_test_nodes; k++ {
			test_nodes = append(test_nodes, k)
		}

		fmt.Println("start ECCPoW with no VCT function")
		for i := 0; i < 100; i++ {
			ldpcDecoding.RunLDPC(test_nodes)

			cmd := exec.Command("python", "temp.py")
			err := cmd.Run()
			if err != nil {
				fmt.Println(err.Error())
			}

			fmt.Printf("%d block generated\n", i)
		}

	}

}
