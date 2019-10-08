'use strict';

const { Contract, Context } = require('fabric-contract-api');
const Validations = require('../helpers/validations')

class FilePasswordStorageContext extends Context {
    constructor() {
        super();      
    }
}
    
class FilePasswordStorage extends Contract {
    constructor() {        
        super(FilePasswordStorage.getClass());
    }

    createContext() {
        return new FilePasswordStorageContext();
    }

    /**
     * Instantiate to perform any setup of the ledger that might be required.
     * @param {Context} ctx the transaction context
     */
    async instantiate(ctx) {      
        console.log('============= START: Instantiate the FilePasswordStorage contract =============');

        console.log('============= END: Instantiate the FilePasswordStorage contract =============');
    }

     /**
     * Document password by hash
     *
     * @param {Context} ctx the transaction context
     * @param {String} fileHash 
    */
    async get(ctx, fileHash, signerId, signerMspId) {
        console.info('============= START : GET document password by hash ===========');

        if (fileHash == 0x0) throw new Error("File hash require");
    
        if (!signerId) {
            signerId = ctx.clientIdentity.getID();   
        }

        if (!signerMspId) {
            signerMspId = ctx.clientIdentity.getMSPID();  
        }  

        console.log("Input parameter fileHash : %s", fileHash);
        console.log("Signer Identity id : %s", signerId);
        console.log("Signer Msp id : %s", signerMspId);

        let key = ctx.stub.createCompositeKey(FilePasswordStorage.getClass(), [ fileHash, signerMspId, signerId ]);

        console.log("Сomposite key : %s", key);

        let pwdSig = await ctx.stub.getState(key);
        
        console.log("Document Password %s", pwdSig);
        
        console.info("============= END : GET document password by hash ===========");

        return pwdSig.toString();
    }   

    /**
     * Add document password by hash
     *
     * @param {Context} ctx the transaction context
     * @param {String} fileHash 
     * @param {String} signerMspId 
     * @param {String} signerId 
     * @param {String} pwdSig 
    */
    async add(ctx, fileHash, signerMspId, signerId, pwdSig) {
        console.info('============= START : Add document password by hash ===========');        

        console.log("Input parameter fileHash : %s", fileHash);
        console.log("Input parameter signerMspId : %s", signerMspId);
        console.log("Input parameter signerId : %s", signerId);
        console.log("Input parameter pwdSig : %s", pwdSig);        

        Validations.checkMspId(signerMspId);
        Validations.checkActorId(signerId);

        if (fileHash == 0x0) throw new Error("File hash require");
        if (pwdSig.length == 0) throw new Error("Encrypted file password require");        
     
        let key = ctx.stub.createCompositeKey(FilePasswordStorage.getClass(), [ fileHash, signerMspId, signerId ]);
        let pwdSigFromLedger = await ctx.stub.getState(key);

        if (pwdSigFromLedger != 0) throw new Error("Encrypted file password already exist for this address");
        
        await ctx.stub.putState(key, pwdSig);

        let eventPayload = Buffer.from(JSON.stringify({fileHash:fileHash, signerMspId: signerMspId, signerId: signerId  }));

        ctx.stub.setEvent("FilePasswordAdded", eventPayload); 
        
        console.info('============= END : Add document password by hash ===========');
    }

    async remove(ctx, fileHash) {
        console.info('============= START : Remove document password by hash ===========');

        if (fileHash == 0x0) throw new Error("File hash require");
    
        let signerId = ctx.clientIdentity.getID();
        let signerMspId = ctx.clientIdentity.getMSPID();    
  
        let key = ctx.stub.createCompositeKey(FilePasswordStorage.getClass(), [ fileHash, signerMspId, signerId ]);

        let pwdSigFromLadger = await ctx.stub.getState(key);

        if (pwdSigFromLadger != 0 ) throw new Error("Encrypted file password doesn't exist");
       
        await ctx.stub.deleteState(key);

        let eventPayload = Buffer.from(JSON.stringify({fileHash:fileHash, signerMspId: signerMspId, signerId: signerId  }));

        ctx.stub.setEvent("FilePasswordRemoved", eventPayload);        
       
        console.info('============= END : Remove document password by hash ===========');
    }
 
    static getClass() {
        return 'org.onlyonet.filepasswordstorage';
    }
}

module.exports = FilePasswordStorage;