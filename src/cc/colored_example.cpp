
#include <cc/eval.h>
#include <script/cc.h>
#include <script/script.h>
#include <cryptoconditions.h>

/*

# Using Hoek to mangle colored coin transactions

# Install haskell stack & hoek

curl -sSL https://get.haskellstack.org/ | sh
git clone https://github.com/libscott/hoek; cd hoek; stack install

# Let...

addr=RHTcNNYXEZhLGRcXspA2H4gw2v4u6w8MNp
wif=UsNAMqFwntEpuFBTbG28e3uAJxBNRM8Vi5FxAqHfoRJJNoZ84Esj
pk=02184e11939da3805808cd18921a8b592b98bbaf9f506da8b272ebc3c5fa4d045c

# Our CC is a 2 of 2 where the subconditions are an secp256k1, and an EVAL code calling 0x28 (EVAL_COLOREDCOIN).

cc='{"type":"threshold-sha-256","threshold":2,"subfulfillments":[{"type":"eval-sha-256","code":"28"},{"type":"secp256k1-sha-256","publicKey":"02184e11939da3805808cd18921a8b592b98bbaf9f506da8b272ebc3c5fa4d045c"}]}'

# 1. Create a colored coin: Just use regular inputs and only colored outputs

createTx='{"inputs": [{"txid":"51b78168d94ec307e2855697209275d477e05d8647caf29cb9e38fb6a4661145","idx":0,"script":{"address":"'$addr'"}}],"outputs":[{"amount":10,"script":{"condition":'$cc'}}]}'

# 2. Transfer a colored coin: use CC inputs, CC outputs, and an OP_RETURN output with the txid of the tx that created the colored coin (change the txid):

transferTx='{"inputs": [{"txid":"51b78168d94ec307e2855697209275d477e05d8647caf29cb9e38fb6a4661145","idx":0,"script":{"fulfillment":'$cc'}}],"outputs":[{"amount":0,"script":{"op_return":"cafabda044ac904d56cee79bbbf3ed9b3891a69000ed08f0ddf0a3dd620a3ea6"}},{"amount":10,"script":{"condition":'$cc'}}]}'

# 3. Sign and encode

function signEncodeTx () {
    signed=`hoek signTx '{"privateKeys":["'$wif'"],"tx":'"$1"'}'`;
    hoek encodeTx "$signed"
}

signEncodeTx "$createTx"
signEncodeTx "$transferTx"

*/


CC* GetCryptoCondition(CScript const& scriptSig)
{
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> ffbin;
    if (scriptSig.GetOp(pc, opcode, ffbin))
        return cc_readFulfillmentBinary((uint8_t*)ffbin.data(), ffbin.size()-1);
}

bool IsColoredCoinInput(CScript const& scriptSig)
{
    CC* cond;
    if (!(cond = GetCryptoCondition(scriptSig)))
        return false;

    // Recurse the CC tree to find colored coin condition
    auto findEval = [&] (CC *cond, struct CCVisitor _) {
        bool r = cc_typeId(cond) == CC_Eval && cond->codeLength == 1 && cond->code[0] == EVAL_COLOREDCOIN;
        // false for a match, true for continue
        return r ? 0 : 1;
    };
    CCVisitor visitor = {findEval, (uint8_t*)"", 0, NULL};
    bool out =! cc_visit(cond, visitor);
    cc_free(cond);
    return out;
}

// Get the coin ID from opret
bool DecodeOpRet(CScript const& scriptPubKey, uint256 &coinId)
{
    std::vector<uint8_t> vopret;
    GetOpReturnData(scriptPubKey, vopret);
    return E_UNMARSHAL(vopret, ss >> coinId);
}

bool IsColoredCoinTx(uint256 coinId, CTransactionRef& inputTx)
{
    // Either the tx will be a CREATE or a TRANSFER.
    unsigned int r = 0;
    for (unsigned int i=0; i<inputTx->vin.size(); i++)
        r += IsColoredCoinInput(inputTx->vin[i].scriptSig) ? 1 : 0;

    if (r == inputTx->vin.size())
    {
        // It's a TRANSFER, check coin ID
        uint256 inputCoinId;
        if (!DecodeOpRet(inputTx->vout[0].scriptPubKey, inputCoinId))
            return false;
        return inputCoinId == coinId;
    }
    else if (r == 0)
    {
        // It's a CREATE, compare hash directly
        return coinId == inputTx->GetHash();
    }

    // Mixed inputs, should never happen
    fprintf(stderr, "Illegal state detected, mixed inputs for colored coin at: %s\n",
            coinId.GetHex().data());
    return false;
}

/*
 * Colored coins using CC defines 2 possible types of transaction, a CREATE and a TRANSFER.
 * A CREATE has only regular (non CC) inputs, and a TRANSFER has only CC inputs.
 *
 * If the colored coin EVAL routine is being called, then the tx is inevitably a TRANSFER
 * becuase in the case of a CREATE routine, no CC is triggered.
 *
 * The coin ID is the ID of the CREATE transaction.
 */

bool ColoredCoinExample(Eval* eval, std::vector<uint8_t> paramsNull, const CTransaction &tx, unsigned int nIn)
{
    // Don't expect params
    if (paramsNull.size() != 0) return eval->Invalid("Cannot have params");

    // Expect output 0 to be an opreturn containing move data
    if (tx.vout.size() == 0) return eval->Invalid("no-vouts");
    uint256 coinId;
    if (!DecodeOpRet(tx.vout[0].scriptPubKey, coinId))
        return eval->Invalid("Invalid opreturn payload");

    // Check inputs
    for (int i=0; i<tx.vin.size(); i++) {
        // All inputs must be colored coin inputs
        if (!IsColoredCoinInput(tx.vin[i].scriptSig))
            return eval->Invalid("Non colored input detected");

        // We also need to validate that our input transactions are legit - either they
        // themselves have CC inputs of the same type, or, they have a token defition and
        // no CC inputs.
        CTransactionRef inputTx;
        uint256 hashBlock;
        if (!eval->GetTxUnconfirmed(tx.vin[i].prevout.hash, inputTx, hashBlock))
            return eval->Invalid("This should never happen");
        if (!IsColoredCoinTx(coinId, inputTx))
            return eval->Invalid("Non colored / wrong color input tx");
    }

    // We're unable to ensure that all the outputs have the correct
    // CC Eval code because we only have the scriptPubKey which is a hash of the
    // condition. The effect of this is that we cannot control the outputs, and therefore
    // are able to burn or "lose" units or our colored token and they will be spent as the
    // regular chain token, but we are able to control when units of the colored coin get
    // created because we can always vet the inputs.
    //
    // Units of the colored token are always 1:1 with the token being input. No additional
    // supply is created on the chain. Effectively, fees are paid in units of the colored token.
    // This leaves something to be desired, because for example, if you wanted to create a
    // single asset that could transfer ownership, usually you would create an asset with a 
    // supply of 1, ie can not be divided further, however in this case there would be nothing
    // left to pay fees with. Implementing separate supply and other details are possible, by
    // encoding further information in the OP_RETURNS.

    // It's valid
    return true;
}
