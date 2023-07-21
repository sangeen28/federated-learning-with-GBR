def main():
    print("from main")
    start3 = time.time()
    dst = "Zero"
   # myGroup = group.P256
    myGroup = ec.SECP256R1()
    curvetype = "P256"
    argCount = len(sys.argv[1:])
    if argCount > 0:
        curvetype = sys.argv[1]
    if argCount > 1:
        dst = sys.argv[2]
    if curvetype == "P256":
        myGroup = ec.SECP256R1()
    elif curvetype == "P384":
        myGroup = ec.SECP256R1()
    elif curvetype == "P521":
        myGroup = ec.SECP256R1()
   # x = random.randrange(0, ec.SECP256R1().order())
    x = ec.SECP256R1.generate_random_non_zero_scalar()    
   # x = myGroup.RandomNonZeroScalar(rand.Reader)
    H = myGroup.RandomElement(rand.Reader)
    X = myGroup.NewElement()
    X.Mul(H, x)
    rnd = rand.Reader
    V, r = GenProof(myGroup, H, X, x, b"Peggy", b"Victor", bytes(dst), rnd)
    verify = Verify(myGroup, H, X, V, r, b"Peggy", b"Victor", bytes(dst))
    print("Value to prove (x): %v\n\n", x)
    print("Public value (X):\n%v\n\n", X)
    print("Curve used: %s\n\n", curvetype)
    print("Domain separation: %s\n\n", dst)
    if verify == True:
        print("Proof (V):\n%v\n\nr: %v\n\n", V, r)
        print("Verify: True")
    else:
        fmt.Printf("ZKP failed")
    elapsed3 = time.now() - start3
    print("time taken by complete process is %s", elapsed3)



if __name__ == "__main__":
    main()
def gen_proof(my_group, H, X, x, peggy_id, victor_id, dst, rnd):
    start = time.time()
    v = my_group.random_non_zero_scalar(rnd)
    V = my_group.new_element()
    V.mul(H, v)

    # Hash (H | V | X | peggy_id | victor_id) for challenge
    H_byte = H.marshal_binary()
    V_byte = V.marshal_binary()
    X_byte = X.marshal_binary()

    hash_byte = H_byte + V_byte + X_byte + peggy_id + victor_id
    c = hashlib.sha256(hash_byte + dst).digest()

    xc = my_group.new_scalar()
    xc.mul(c, x)
    r = v.copy()
    r.sub(r, xc)

    elapsed = time.time() - start
    print("Time taken by challenge is", elapsed)

    return V, r
def verify(myGroup, H, X, V, r, peggyID, victorID, dst):
    start2 = time.time()
    HByte = H.MarshalBinary()
    if errByte != None:
        raise Exception(errByte)
    
    VByte = V.MarshalBinary()
    if errByte != None:
        raise Exception(errByte)
    
    XByte = X.MarshalBinary()
    if errByte != None:
        raise Exception(errByte)
    
    hashByte = HByte + VByte + XByte + peggyID + victorID
    
    c = myGroup.HashToScalar(hashByte, dst)
    
    rH = myGroup.NewElement()
    rH.Mul(H, r)
    
    cR = myGroup.NewElement()
    cR.Mul(X, c)
    
    rH.Add(rH, cR)
    
    elapsed2 = time.time() - start2
    print("time taken by verification is", elapsed2)
    
    return V.IsEqual(rH)
