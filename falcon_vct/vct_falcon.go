package vct

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"falcon_vct/falcon"
	"fmt"
	"time"
)

const log1024 uint = 10

type set_probablity struct {
    probablity uint8
    norm_bound uint32
}

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

func Prove(PublicKey, PrivateKey, m []byte) (pi, hash []byte, err error) {
    // 1. 서명 생성 (에러는 무시하지 말자)
    sig, err := sk.SignCompressed(m)
    if err != nil {
        return nil, nil, err
    }

    // 2. 서명에 SHA-256 적용해서 "압축" (32바이트 해시)
    sum := sha256.Sum256(sig) // [32]byte

    // 3. pi = 서명, hash = 서명 해시
    return sig, sum[:], nil
}

// Verify: pi가 유효한지 확인
func Verify(PublicKey, PrivateKey, pi []byte) (bool, error) {
    // pi = 서명 (compressed signature)
    if err := pk.Verify(pi, m); err != nil {
        // 검증 실패
        return false, err
    }
    // 검증 성공
    return true, nil
}

// 내부 공용 함수: seed가 nil이면 랜덤, 아니면 주어진 seed 사용
func performFalconVCT(id int, msg []byte, nthreshold uint32, seed []byte) Nodes {
    startTime := time.Now()

    // seed 없으면 랜덤 seed 생성 (기존 동작 유지)
    if seed == nil || len(seed) == 0 {
        seed = make([]byte, 64)
        if _, err := rand.Read(seed); err != nil {
            panic(err)
        }
    }

    pk, sk, _ := falcon.GenerateKey(seed)

    sig, _ := sk.SignCompressed(msg)
    err := pk.Verify(sig, msg)

    var verify_res string
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

    var VCT_res bool
    if norm < nthreshold {
        VCT_res = true
    } else {
        VCT_res = false
    }

    elapsedTime := time.Since(startTime)

    return Nodes{
        id:       fmt.Sprintf("node_%d", id),
        pi:       enc_sig,
        norm:     int(norm),
        VCT_res:  VCT_res,
        vrfy_res: verify_res,
        exe_time: elapsedTime.String(),
    }
}


// 기존 공개 함수는 그대로 두고, 내부 공용 함수만 호출
// => 외부 코드(main 등)는 수정할 필요 없음.
func PerformFalconVCT(id int, msg []byte, nthreshold uint32) Nodes {
    return performFalconVCT(id, msg, nthreshold, nil)
}

// norm_s는 기존 그대로 두면 됨
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
