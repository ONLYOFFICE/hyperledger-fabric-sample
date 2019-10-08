'use strict';

const { Contract, Context } = require('fabric-contract-api');
const Validations = require('../helpers/validations')

class PublicKeyStorageContext extends Context {
    constructor() {
        super();      
    }
}
    
class PublicKeyStorage extends Contract {
    constructor() {        
        super(PublicKeyStorage.getClass());
    }

    createContext() {
        return new PublicKeyStorageContext();
    }

  
    /**
     * Instantiate to perform any setup of the ledger that might be required.
     * @param {Context} ctx the transaction context
     */    
    async instantiate(ctx) {    
        console.log('============= START: Instantiate the PublicKeyStorage contract =============');

        console.log('============= END: Instantiate the PublicKeyStorage contract =============');
    }

    /**
     * Set actor publicKey and signature
     *
     * @param {Context} ctx the transaction context
     * @param {String} publicKey 
     * @param {String} signature 
    */
    async set(ctx, publicKey, signature) {     
        console.info('============= START : Set actor publicKey and signature ===========');

        let signerMspId = ctx.clientIdentity.getMSPID();    
        let signerId = ctx.clientIdentity.getID();

        console.log("Current parameter signerMspId : %s", signerMspId);
        console.log("Current parameter signerId : %s", signerId);
     
        let key = ctx.stub.createCompositeKey(PublicKeyStorage.getClass(), [ signerMspId, signerId ]);
        let value =  Buffer.from(JSON.stringify({publicKey:publicKey, signature:signature}));

        console.info("Composite key: %s", key);

        await ctx.stub.putState(key, value);     

        console.info('============= END : Set actor publicKey and signature ===========');
    }

    
    /**
     * 
     *
     * @param {Context} ctx the transaction context
     * @param {String} publicKey 
     * @param {String} signature 
    */
    async get(ctx, signerMspId, signerId) {
        console.info('============= START : Get publicKey and signature ===========');

        console.log("Input parameter signerMspId : %s", signerMspId);
        console.log("Input parameter signerId : %s", signerId);

        Validations.checkMspId(signerMspId);
        Validations.checkActorId(signerId);
     
        let key = ctx.stub.createCompositeKey(PublicKeyStorage.getClass(), [ signerMspId, signerId ]);
        let value = await ctx.stub.getState(key);

        console.info("Composite key: %s", key);
        
        console.info('============= END : Get publicKey and signature ===========');
        
        return JSON.parse(value.toString());
    }   
   
    static getClass() {
        return 'org.onlyonet.publickeystorage';
    }
}

module.exports = PublicKeyStorage;