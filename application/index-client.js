'use strict';

const { FileSystemWallet, Gateway, X509WalletMixin } = require('fabric-network');
const fs = require('fs');
const path = require('path');
const { Certificate, PrivateKey } = require('@fidm/x509');

const ccpPath = path.resolve(__dirname, '..', 'gateway', 'production-connection.json');
//const ccpPath = path.resolve(__dirname, '..', 'gateway', 'development-connection.json');

const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);
const nconf = require('nconf');

const elliptic = require('elliptic');
const { KEYUTIL } = require('jsrsasign');
const eccrypto = require("eccrypto");

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, label, printf } = format;

const express = require('express'),     
      app = express(),
      bodyParser = require('body-parser'),
      jsonParser = bodyParser.json(),    
      morgan = require('morgan'), 
      logger = createLogger({
        level: 'debug',
        format: combine(
            timestamp({format: 'YYYY-MM-DD | HH:mm:ss'}),
            printf(({ level, message, label, timestamp }) => {
                return `${timestamp} | main | ${level.padEnd(7).toUpperCase()} | asc.common.client | 000000 | ${message}`;
            })  
        ),
        transports: [
          new transports.File({ filename: 'logs/error.log', level: 'error' }),
          new transports.File({ filename: 'logs/common.log' }),
          new transports.Console({ colorize: true })  
        ]
      });


const NETWORK_CHAINCODE_NAME = "onlyonet-chaincode";
const NETWORK_CHANNEL_NAME = "onlyonet-channel";
const NETWORK_CONTRACT_FILEPASSWORDSTRAGE_NAME = "org.onlyonet.filepasswordstorage";
const NETWORK_CONTRACT_PUBLICKEYSTORAGE_NAME = "org.onlyonet.publickeystorage";

nconf.use('memory');

nconf.argv().env();

if (nconf.get('NODE_ENV'))
    nconf.file(nconf.get('NODE_ENV'),{ file: path.join(__dirname, "config/", nconf.get('NODE_ENV')+'.json') });

nconf.file("development", path.join(__dirname, "config/", 'development.json'));


nconf.defaults({
   "port": 3000,
   "walletPath": path.join(process.cwd(), 'wallet')
});

nconf.required(['port', 'walletPath']);

const port = nconf.get('port');
const walletPath = nconf.get('walletPath');


app.listen(port, (err) => {
    if (err) {
        logger.error("something bad happened " + err);

        return;
    } 

    logger.info("server is listening on " + port);
});

app.use(jsonParser);

const accessLogStream = fs.createWriteStream(path.join(__dirname, 'logs/access.log'), { flags: 'a' })

app.use(morgan('combined', { stream: accessLogStream }))

function parseCertificateDN(dn) {
    var result = "";
    
    for (var i = 0; i < dn.attributes.length; i++) {

        var shortName = dn.attributes[i].shortName;
        var value = dn.attributes[i].value;
        var splitter = "/";

        if (i > 0) {
            splitter = (dn.attributes[i].oid == dn.attributes[i-1].oid) ? "+" : "/";          
        }
        
        result += splitter + shortName  + "=" + value;            
    }

    return result;
}

function getClientId(publicKeyECDSA) {
    const certificateDecode = Certificate.fromPEM(publicKeyECDSA);     
    return `x509::${parseCertificateDN(certificateDecode.subject)}::${parseCertificateDN(certificateDecode.issuer)}`; 
}

app.post("/system/blockchaininfo", async (req, resp) => {
    logger.debug('START : POST /system/blockchaininfo Show blockchain info');
        
    let body = req.body;           
    let enrollmentID = body.enrollmentID;   

    try {
        // Create a new file system based wallet for managing identities.
        const wallet = new FileSystemWallet(walletPath);

        logger.debug(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(enrollmentID);

        if (!userExists) {
            throw new Error(`An identity for the user "${enrollmentID}" does not exist in the wallet`);
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();

        await gateway.connect(ccp, { wallet, identity: enrollmentID, discovery: { enabled: false } });  

        const network = await gateway.getNetwork(NETWORK_CHANNEL_NAME);        
        const dataset = await network.channel.queryInfo();

        const userIdentity = await wallet.export(enrollmentID);        

        resp.status(200).json({blockNumber: dataset.height.toString(), 
                               currentBlockHash: dataset.currentBlockHash.toString('hex'), 
                               previousBlockHash: dataset.previousBlockHash.toString('hex'),
                               channelName: NETWORK_CHANNEL_NAME, 
                               clientId: getClientId(userIdentity.certificate) });
        resp.end();

    } catch (error) {
        logger.error(`Failed to get blockchain info by user '${enrollmentID}': ${error}`);

        resp.status(503).json({"error": error});
        resp.end();
    }

    logger.debug('END : POST /system/blockchaininfo Show blockchain info');
});

app.post("/user/wallet", async (req, resp) => {
    logger.debug('START : POST /user/wallet Set user wallet');
    
    let body = req.body;           
    let enrollmentID = body.enrollmentID;  
    let publicKeyECDSA = Buffer.from(body.publicKeyECDSA, 'base64').toString('utf8'); 
    let privateKeyECDSA = Buffer.from(body.privateKeyECDSA, 'base64').toString('utf8'); 
    let mspId = body.mspId;

    try {

        // Create a new file system based wallet for managing identities.
        const wallet = new FileSystemWallet(walletPath);

        logger.debug(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(enrollmentID);

        if (userExists) {
            throw new Error(`An identity for the user "${enrollmentID}" already exist in the wallet`);
        }
        
        const identity = {
            "type":"X509",
            "mspId": mspId,
            "certificate": publicKeyECDSA,
            "privateKey": privateKeyECDSA
        };

        await wallet.import(enrollmentID, identity);
       
        resp.status(200).json({"result": "ok"});
        resp.end();

    } catch (error) {
        logger.error(`Failed to import wallet for user '${enrollmentID}': ${error}`);

        resp.status(503).json({"error": error});
        resp.end();
    }   

    logger.debug('START : POST /user/wallet Set user wallet');
});

app.post("/user/eccrypto/generate", async (req, resp) => {
    logger.debug('START : POST /user/eccrypto/generate Generate ECIES keypair');

    let body = req.body;           
    let enrollmentID = body.enrollmentID;   

    try {

        // Create a new file system based wallet for managing identities.
        const wallet = new FileSystemWallet(walletPath);
        
        logger.debug(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(enrollmentID);

        if (!userExists) {
            throw new Error(`An identity for the user "${enrollmentID}" does not exist in the wallet`);
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: enrollmentID, discovery: { enabled: false } });
       
        const userIdentity = await wallet.export(enrollmentID);
             
        const privateKeyPEM = userIdentity.privateKey;
        const { prvKeyHex } = KEYUTIL.getKey(privateKeyPEM); 

        const EC = elliptic.ec;
        const ecdsaCurve = elliptic.curves['p256'];

        const ecdsa = new EC(ecdsaCurve);
        const signKey = ecdsa.keyFromPrivate(prvKeyHex, 'hex');
       
        const privateKeyECIES = eccrypto.generatePrivate();
        const publicKeyECIES = eccrypto.getPublic(privateKeyECIES);
        
        const sig = ecdsa.sign(publicKeyECIES, signKey);

        const signature = Buffer.from(sig.toDER());

        const network = await gateway.getNetwork(NETWORK_CHANNEL_NAME);
      
        const contract = network.getContract(NETWORK_CHAINCODE_NAME, NETWORK_CONTRACT_PUBLICKEYSTORAGE_NAME); 
       
        await contract.submitTransaction('set', publicKeyECIES.toString('base64'), signature.toString('base64'));
      
        logger.debug('END : POST /user/eccrypto/generate Generate ECIES keypair');

        resp.status(200).json({publicKeyECIES: publicKeyECIES.toString('base64'), privateKeyECIES: privateKeyECIES.toString('base64')});
        resp.end();

    } catch (error) {
        logger.error(`Failed to register user '${enrollmentID}': ${error}`);

        resp.status(503).json({"error": error});
        resp.end();
    }
});

app.post("/document/password", async (req, resp) => {
    logger.debug('START : POST /document/password : Add document by hash and password');

    const body = req.body;
    const fileHash = body.fileHash;
    const enrollmentID = body.enrollmentID;
    const filePassword = body.filePassword;
    var recipientPublicKeyECDSA = body.recipientPublicKeyECDSA;
   
    
    try {

        const wallet = new FileSystemWallet(walletPath);

        logger.debug(`Wallet path: ${walletPath}`);
       
        // Check to see if we've already enrolled the user.        
        const userExists = await wallet.exists(enrollmentID);

        if (!userExists) {
            throw new Error(`An identity for the user "${enrollmentID}" does not exist in the wallet`);
        }

        if (!recipientPublicKeyECDSA) {
            const enrollmentWallet = await wallet.export(enrollmentID);
            recipientPublicKeyECDSA = enrollmentWallet.certificate;
        }
        else {
            recipientPublicKeyECDSA = Buffer.from(body.recipientPublicKeyECDSA, 'base64').toString('utf8'); 
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: enrollmentID, discovery: { enabled: false } });       
        
        const network = await gateway.getNetwork(NETWORK_CHANNEL_NAME);
        var contract = network.getContract(NETWORK_CHAINCODE_NAME, NETWORK_CONTRACT_PUBLICKEYSTORAGE_NAME); 
        
        const signerId = getClientId(recipientPublicKeyECDSA);
        const signerMspId = gateway.getCurrentIdentity().getIdentity().getMSPId();
             
        var resultFromContract = await contract.evaluateTransaction('get', signerMspId, signerId);

        const publicKeyECIES = Buffer.from(JSON.parse(resultFromContract.toString()).publicKey, 'base64');

        contract = network.getContract(NETWORK_CHAINCODE_NAME, NETWORK_CONTRACT_FILEPASSWORDSTRAGE_NAME); 

        let encryptedPwd = await eccrypto.encrypt(publicKeyECIES, Buffer.from(filePassword));
             
        await contract.submitTransaction('add', fileHash, signerMspId, signerId, JSON.stringify(encryptedPwd)); 
        
        resp.status(200);

        logger.debug('END : POST /document/password : Add document by hash and password');

        resp.end();

    } catch (error) {
        logger.error(`Failed to register user "${enrollmentID}": ${error}`);
        
        resp.status(503).json({"error": error});
        resp.end();
    }
});


app.post("/document/password/exist", async (req, resp) => {
    logger.debug('START : GET /document/password/exist Check document password by hash is exist');

    const body = req.body;
    const publicKeyECDSA =  Buffer.from(body.publicKeyECDSA, 'base64').toString('utf8');
    const enrollmentID = body.enrollmentID;
    const fileHash = body.fileHash;
  
    try {

        const wallet = new FileSystemWallet(walletPath);

        logger.debug(`Wallet path: ${walletPath}`);
       
        // Check to see if we've already enrolled the user.        
        const userExists = await wallet.exists(enrollmentID);

        if (!userExists) {
            throw new Error(`An identity for the user "${enrollmentID}" does not exist in the wallet`);
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: enrollmentID, discovery: { enabled: false } });       
        
        const network = await gateway.getNetwork(NETWORK_CHANNEL_NAME);
        const contract = network.getContract(NETWORK_CHAINCODE_NAME, NETWORK_CONTRACT_FILEPASSWORDSTRAGE_NAME); 

        const signerId = getClientId(publicKeyECDSA);
        const signerMspId = gateway.getCurrentIdentity().getIdentity().getMSPId();
    
        let encryptedPwd = await contract.evaluateTransaction('get', fileHash, signerId,signerMspId); 
        
        if (encryptedPwd.length != 0)
            resp.status(200).json({"result": "true"});
        else
            resp.status(200).json({"result": "false"});
      
        logger.debug('END : POST /document/password : Add document by hash and password');

        resp.end();    
    } catch (error) {
        logger.error(error);
             
        resp.status(503).json({"error": error});
        resp.end();
    }
  
    logger.debug('END : GET /document/password/exist Get document password by hash  is exist');
});

app.post("/document/password/get", async (req, resp) => {
    logger.debug('START : GET /document/password Get document password by hash');

    const body = req.body;
    const enrollmentID = body.enrollmentID;
    const privateKeyECIES = Buffer.from(body.privateKeyECIES,"base64");
    const fileHash = body.fileHash;

    try {
        // Create a new file system based wallet for managing identities.
        const wallet = new FileSystemWallet(walletPath);  
          
        logger.debug(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(enrollmentID);

        if (!userExists) {
            throw new Error(`An identity for the user "${enrollmentID}" does not exist in the wallet`);
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: enrollmentID, discovery: { enabled: false } });
      
        const network = await gateway.getNetwork(NETWORK_CHANNEL_NAME);
        const contract = network.getContract(NETWORK_CHAINCODE_NAME, NETWORK_CONTRACT_FILEPASSWORDSTRAGE_NAME); 

        let encryptedPwd = await contract.evaluateTransaction('get', fileHash); 
        
        encryptedPwd = encryptedPwd.toString();

        logger.debug(`Wallet path: ${encryptedPwd}`);


        let filePassword = "";
    
        if (encryptedPwd)
        {  
           encryptedPwd = JSON.parse(encryptedPwd);
           encryptedPwd.ciphertext = Uint8Array.from(encryptedPwd.ciphertext.data);
           encryptedPwd.ephemPublicKey = Buffer.from(encryptedPwd.ephemPublicKey.data);
           encryptedPwd.iv = Buffer.from(encryptedPwd.iv.data);
           encryptedPwd.mac = Uint8Array.from(encryptedPwd.mac.data); 
           filePassword = await eccrypto.decrypt(privateKeyECIES,encryptedPwd );    
           filePassword = filePassword.toString();
        } 

        resp.status(200).json({"password": filePassword});
        resp.end();
        
        logger.debug('END : GET /document/password Get document password by hash');

    } catch (error) {
        logger.error(error);
        console.error(`Failed to get document password by hash: ${error}`);

        resp.status(503).json({"error": error});
        resp.end(); 
    }
});

app.post("/document/sign", async (req, resp) => {
    throw new Error("Not Implemented");   
    logger.debug('START : POST /document/sign');

    const body = req.body;
    const enrollmentID = body.enrollmentID;

    logger.debug('END : POST /document/sign');  
});