package vct

import (
    "crypto/rand"
    "encoding/hex"
    "falcon_vct/falcon"
    "fmt"
    mathrand "math/rand"
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

// norm_s는 서명 (s1, s2)의 제곱 놈(squared norm)을 계산합니다.
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

// PerformFalconVCT는 단일 Falcon VCT를 수행합니다.
// 키 생성, 서명, 검증 및 놈(norm) 확인을 포함합니다.
func PerformFalconVCT(id int, msg []byte, nthreshold uint32) Nodes {
    startTime := time.Now()
    mathrand.Seed(time.Now().UnixNano())
    seed := make([]byte, 64)
    rand.Read(seed)
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