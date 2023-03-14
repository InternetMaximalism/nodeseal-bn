import {LWEencrypt, LWEsmul,decryptMatrixToBN, LWEaddMatrix} from '../index.js'
import {LWEsetup} from '../lib/lwesetup.js'
import BN from 'bn.js';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'crypto';

describe("pow", async function() {

    const setup = await LWEsetup();

    it("LWE mul", async function() {
        const setup = await LWEsetup();
        var bn0 = new BN("1111111123875498347595678909876545678904");
        var bn1 = new BN("111111114850938450954387539848745298347598");

        var cipherTex0 = await LWEencrypt(setup.encryptor,bn0,setup.encoder);
        var cipherTex = await LWEsmul(setup.evaluator,setup.encoder,cipherTex0,bn1,setup.seal);
        console.log(cipherTex.typeinfo);
        var bnlast = await decryptMatrixToBN(setup.decryptor,cipherTex.contents,setup.encoder);

        assert.equal(bnlast.toString(),bn0.mul(bn1).toString());

        var addedCihperTex = await LWEaddMatrix(setup.evaluator,cipherTex.contents,cipherTex.contents,setup.seal);
        var bnadded = await decryptMatrixToBN(setup.decryptor,addedCihperTex.contents,setup.encoder);
        assert.equal(bnadded.toString(),bn0.mul(bn1).mul(new BN(2)).toString())
      
    });
  
  });

//test1

const setup = await LWEsetup();
var bn0 = new BN("1111111123875498347595678909876545678904");
var bn1 = new BN("111111114850938450954387539848745298347598");

var cipherTex0 = await LWEencrypt(setup.encryptor,bn0,setup.encoder);
var cipherTex = await LWEsmul(setup.evaluator,setup.encoder,cipherTex0,bn1,setup.seal);
console.log(cipherTex.typeinfo);
var bnlast = await decryptMatrixToBN(setup.decryptor,cipherTex.contents,setup.encoder);

console.log(bnlast.toString());
console.log(bn0.mul(bn1).toString())

var addedCihperTex = await LWEaddMatrix(setup.evaluator,cipherTex.contents,cipherTex.contents,setup.seal);
var bnadded = await decryptMatrixToBN(setup.decryptor,addedCihperTex.contents,setup.encoder);
console.log(bnadded.toString());
console.log(bn0.mul(bn1).mul(new BN(2)).toString())