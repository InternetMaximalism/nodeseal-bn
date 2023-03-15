import {LWEencrypt, LWEsmul,decryptMatrixToBN, LWEaddMatrix} from '../index.js'
import {LWEsetup} from '../lib/lwesetup.js'
import BN from 'bn.js';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'crypto';

describe("unit tests", async function() {

    // LWEmul function test with random numbers
    it("LWE mul", async function() {
        const setup = await LWEsetup();

        const value0 = randomBytes(32);
        const value1 = randomBytes(32);
        const bn0 = new BN(value0.toString('hex'), 16);
        const bn1 = new BN(value1.toString('hex'), 16);

        var cipherTex0 = LWEencrypt(setup.encryptor,bn0,setup.encoder);
        var cipherTex = LWEsmul(setup.evaluator,setup.encoder,cipherTex0,bn1,setup.seal);

        var bnlast = decryptMatrixToBN(setup.decryptor,cipherTex.contents,setup.encoder);

        assert.equal(bnlast.toString(),bn0.mul(bn1).toString());

        var addedCihperTex = LWEaddMatrix(setup.evaluator,cipherTex.contents,cipherTex.contents,setup.seal);
        var bnadded = decryptMatrixToBN(setup.decryptor,addedCihperTex.contents,setup.encoder);
        assert.equal(bnadded.toString(),bn0.mul(bn1).mul(new BN(2)).toString())
      
    });

    // LWEaddMatrix function test with random numbers
    it("LWE addMatrix",async function() {

        const setup = await LWEsetup();

        const value0 = randomBytes(32);
        const value1 = randomBytes(32);
        const bn0 = new BN(value0.toString('hex'), 16);
        const bn1 = new BN(value1.toString('hex'), 16);
        
        var cipherTex0 = LWEencrypt(setup.encryptor,bn0,setup.encoder);
        var cipherTexMetrix0 = LWEsmul(setup.evaluator,setup.encoder,cipherTex0,new BN(1),setup.seal);

        var cipherTex1 = LWEencrypt(setup.encryptor,bn1,setup.encoder);
        var cipherTexMetrix1 = LWEsmul(setup.evaluator,setup.encoder,cipherTex1,new BN(1),setup.seal);
        
        var addedCihperTex = LWEaddMatrix(setup.evaluator,cipherTexMetrix0.contents,cipherTexMetrix1.contents,setup.seal);
        var bnadded = decryptMatrixToBN(setup.decryptor,addedCihperTex.contents,setup.encoder);

        assert.equal(bnadded.toString(),bn0.add(bn1).toString());
        
    });
  
});