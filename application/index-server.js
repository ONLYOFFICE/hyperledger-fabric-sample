'use strict';

const { FileSystemWallet, Gateway, X509WalletMixin } = require('fabric-network');
const fs = require('fs');
const path = require('path');
const ccpPath = path.resolve(__dirname, '..', 'gateway', 'production-connection.json');

//const ccpPath = path.resolve(__dirname, '..', 'gateway', 'development-connection.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);
const nconf = require('nconf');

const FabricCAServices = require('fabric-ca-client');

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, label, printf } = format;

const express = require('express'),     
      app = express(),
      bodyParser = require('body-parser'),
      morgan = require('morgan'), 
      jsonParser = bodyParser.json(),     
      logger = createLogger({
        level: 'debug',
        format: combine(
            timestamp({format: 'YYYY-MM-DD | HH:mm:ss'}),
            printf(({ level, message, label, timestamp }) => {
                return `${timestamp} | main | ${level.padEnd(7).toUpperCase()} | asc.common.server | 000000 | ${message}`;
            })  
        ),
        transports: [
          new transports.File({ filename: 'logs/error.log', level: 'error' }),
          new transports.File({ filename: 'logs/common.log' }),
          new transports.Console({ colorize: true })  
        ]
      });


nconf.use('memory');

nconf.argv().env();

if (nconf.get('NODE_ENV'))
    nconf.file(nconf.get('NODE_ENV'),{ file: path.join(__dirname, "config/", nconf.get('NODE_ENV')+'.json') });

nconf.file("development", path.join(__dirname, "config/", 'development.json'));

nconf.defaults({
   "port": 3001,
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

app.post("/user/enroll/admin", async (req, resp) => {
    try {        
        // Create a new CA client for interacting with the CA.
        const caURL = ccp.certificateAuthorities['rca.onlyoffice.dev'].url;
   //     const caName = ccp.certificateAuthorities['rca.onlyoffice.dev'].caName;
     //   const tlsCACertsPath = path.resolve(__dirname, '..', 'gateway', ccp.certificateAuthorities['rca.onlyoffice.dev'].tlsCACerts.path);
    //    const tlsCACerts = fs.readFileSync(tlsCACertsPath, 'utf8');
    //    const tlsCACertsVerify = ccp.certificateAuthorities['rca.onlyoffice.dev'].httpOptions.verify;

        const ca = new FabricCAServices(caURL);

        // Create a new file system based wallet for managing identities.
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists('admin');

        if (adminExists) {
            throw new Error('An identity for the admin user "admin" already exists in the wallet');
        }
        
        // Enroll the admin user, and import the new identity into the wallet.
        const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: '38N31rX2H2RcJ9z'});
        const identity = X509WalletMixin.createIdentity('ASCMSP', enrollment.certificate, enrollment.key.toBytes());
             

        const identity1 = {
            "type":"X509",
            "mspId":"ASCMSP",
            "certificate":`-----BEGIN CERTIFICATE-----
MIIB6jCCAZGgAwIBAgIUPtwHN+AFbJBev4nlu1oFG0nblKgwCgYIKoZIzj0EAwIw
aDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK
EwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMt
Y2Etc2VydmVyMB4XDTE5MDgyOTE1NTQwMFoXDTIwMDgyODE1NTkwMFowITEPMA0G
A1UECxMGY2xpZW50MQ4wDAYDVQQDEwVhZG1pbjBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABItL+YM7EqJ2Y3G+ts8Kp2/zOw6O5vQKAHQQ9f6GbK8aTGmmtXm2y8PH
6yXqmulDwP0Cz3Rpi5Sr05gj/fG9apqjYDBeMA4GA1UdDwEB/wQEAwIHgDAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBQVkQJWGzMx512j6UiLp3jIg5iMFDAfBgNVHSME
GDAWgBRdYFw1apDohWaxaG0fgYSTO9QwzzAKBggqhkjOPQQDAgNHADBEAiAIMrra
JKUbvG7vNnEpHULCqJ479IYv+GEcsqNyw5WY4AIgW0B3RgyuDgMMraWDG4RQWxSN
KxyWJT3UOXepF8zNLjM=
-----END CERTIFICATE-----`,
            "privateKey":`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmW+TnoPk0kw7XSxS
omGgLaVzkUW/iYeEokfOk8edmxKhRANCAASLS/mDOxKidmNxvrbPCqdv8zsOjub0
CgB0EPX+hmyvGkxpprV5tsvDx+sl6prpQ8D9As90aYuUq9OYI/3xvWqa
-----END PRIVATE KEY-----`
        };

        await wallet.import('admin', identity);
        console.log('Successfully enrolled admin user "admin" and imported it into the wallet');

    } catch (error) {
        logger.error(`Failed to enroll admin: ${error}`);

        resp.status(503).json({"error": error});
        resp.end();
    }
});

app.post("/user/enroll", async (req, resp) => {
    logger.debug('START : POST /user/enroll Register and enroll user');

    let body = req.body;           
    let enrollmentID = body.enrollmentID;
    let enrollmentSecret = body.enrollmentSecret;

    try {      
        
        // Create a new file system based wallet for managing identities.
        const wallet = new FileSystemWallet(walletPath);
      
        logger.debug(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(enrollmentID);

        if (userExists) {
            throw new Error(`An identity for the user ${enrollmentID} already exists in the wallet`);
        }

        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists('admin');
        
        if (!adminExists) {
            throw new Error('An identity for the admin user "admin" does not exist in the wallet');
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'admin', discovery: { enabled: false } });

        // Get the CA client object from the gateway for interacting with the CA.
        const ca = gateway.getClient().getCertificateAuthority();
        const adminIdentity = gateway.getCurrentIdentity();
       
        const customAttributes = [{
             "name":"asc.release", 
             "value":"developer preview",
             "ecert": true 
        }];


        // Register the user, enroll the user, and import the new identity into the wallet.
        const secret = await ca.register({  enrollmentID: enrollmentID, enrollmentSecret: enrollmentSecret, role: 'client', maxEnrollments: 1, attrs: customAttributes }, adminIdentity);
        const enrollment = await ca.enroll({ enrollmentID: enrollmentID, enrollmentSecret: secret });
        const userIdentity = X509WalletMixin.createIdentity('ASCMSP', enrollment.certificate, enrollment.key.toBytes());
   
        logger.info(`Successfully registered and enrolled "${enrollmentID}" user and imported it into the wallet`);
        
        resp.status(200).json({ mspId: userIdentity.mspId, 
                                enrollmentID: enrollmentID, 
                                enrollmentSecret: secret, 
                                publicKeyECDSA: Buffer.from(userIdentity.certificate).toString('base64'), 
                                privateKeyECDSA: Buffer.from(userIdentity.privateKey).toString('base64')
                              });

        logger.debug('END : POST /user/enroll Register and enroll user');

        resp.end();

    } catch (error) {
        logger.error(`Failed to register and enroll user '${enrollmentID}': ${error}`);

        resp.status(503).json({"error": error});
        resp.end();
    }
});
