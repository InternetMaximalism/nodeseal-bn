// Using this setting for big numbers. Avoiding the errors of transparency when some vectors are 0;
// Pls use this library for the calculations of enough big numbers
import SEAL from 'node-seal/allows_wasm_web_umd.js'

export async function LWEsetup() {

    const seal = await SEAL()
    const schemeType = seal.SchemeType.bfv    
    const securityLevel = seal.SecurityLevel.tc128
    const polyModulusDegree = 4096
    const bitSizes = [36,36,37]
    const bitSize = 20
    
    const encParms = seal.EncryptionParameters(schemeType)

    encParms.setPolyModulusDegree(polyModulusDegree)

    encParms.setCoeffModulus(
      seal.CoeffModulus.Create(
        polyModulusDegree,
        Int32Array.from(bitSizes)
      )
    )

    encParms.setPlainModulus(
      seal.PlainModulus.Batching(
        polyModulusDegree,
        bitSize
      )
    )

    const context = seal.Context(
      encParms,
      true,
      securityLevel
    )

    if (!context.parametersSet()) {
      throw new Error('Could not set the parameters in the given context. Please try different encryption parameters.')
    }

    const keyGenerator = seal.KeyGenerator(
      context
    )

    const Secret_key_Keypair_A_ = keyGenerator.secretKey()
    const Public_key_Keypair_A_ = keyGenerator.createPublicKey()
    const PlainText = seal.PlainText();
    const CipherText = seal.CipherText();

    
    const evaluator = seal.Evaluator(context)
    const batchEncoder = seal.BatchEncoder(context)

    const encryptor = seal.Encryptor(
      context,
      Public_key_Keypair_A_
    )
    const decryptor = seal.Decryptor(
      context,
      Secret_key_Keypair_A_
    )
    
    encryptor.encrypt(
      PlainText,
      CipherText
    )

    return {encryptor: encryptor, decryptor: decryptor, evaluator:evaluator, encoder:batchEncoder,seal:seal}
}