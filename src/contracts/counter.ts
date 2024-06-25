import {
    assert,
    ByteString,
    byteString2Int,
    hash256,
    int2ByteString,
    method,
    OpCode,
    sha256,
    SmartContract,
    toByteString,
} from 'scrypt-ts'
import { SHPreimage, SigHashUtils } from './sigHashUtils'

export class Counter extends SmartContract {
    readonly ZEROSAT = toByteString('0000000000000000')

    @method()
    public complete(
        shPreimage: SHPreimage,
        prevTxVer: ByteString,
        prevTxLocktime: ByteString,
        prevTxInputs: ByteString, // Includes input length prefix...
        contractOutputSPK: ByteString, // contract output scriptPubKey
        contractOutputAmount: ByteString, // contract output amount
        contractOutputAmountNew: ByteString, // updated contract output amount
        count: ByteString
    ) {
        // Check sighash preimage.
        const s = SigHashUtils.checkSHPreimage(shPreimage)
        assert(this.checkSig(s, SigHashUtils.Gx))

        // Construct prev tx
        const opreturnOutput = this.ZEROSAT + OpCode.OP_RETURN + count
        const prevTxId = hash256(
            prevTxVer +
                prevTxInputs +
                toByteString('02') +
                contractOutputAmount +
                contractOutputSPK +
                opreturnOutput +
                prevTxLocktime
        )

        // Validate prev tx
        const hashPrevouts = sha256(prevTxId + toByteString('00000000'))
        assert(hashPrevouts == shPreimage.hashPrevouts, 'hashPrevouts mismatch')

        // increment
        const newCount = int2ByteString(byteString2Int(count) + 1n)
        const opreturnOutputNew = this.ZEROSAT + OpCode.OP_RETURN + newCount

        // Enforce outputs
        const hashOutputs = sha256(
            // recurse: same scriptPubKey
            contractOutputAmountNew + contractOutputSPK + opreturnOutputNew
        )
        assert(hashOutputs == shPreimage.hashOutputs, 'hashOutputs mismatch')
    }
}
