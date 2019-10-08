const Validations = class {
    static checkArgsLength(args, expectedLength) {
      if (args.length !== expectedLength) {
        _throw(
          `Invalid number of arguments. Expected ${expectedLength}, got ${
            args.length
          }.`
        );
      }
    }
  
    static isString(arg) {
      if (typeof arg !== "string") {
        _throw(`Invalid argument type. Expected string, got ${typeof arg}.`);
      }
    }
  
    static checkMspId(mspId) {
      if (!mspId || typeof mspId !== "string" || !mspId.endsWith("MSP")) {
        _throw(`Invalid MSPID: ${mspId}, of type: ${typeof mspId}.`);
      }
    }

    static checkActorId(actorId) {
      if (!actorId || typeof actorId !== "string") {
        _throw(`Invalid ACTORID: ${actorId}, of type: ${typeof actorId}.`);
      }   
    }
  
    static isGreaterThanZero(value) {
      if (parseFloat(value) <= 0) {
        _throw(`Parsed version of ${value}, should be > 0.`);
      }
    }
        
    static isSmallerOrEqual(a, b) {
      if (a > b) {
        _throw(`${a} should be <= to ${b}.`);
      }
    }
  
    static isTrueOrFalse(arg) {
      if (arg !== "true" && arg !== "false") {
        _throw(`${arg} should equal 'true' or 'false'.`);
      }
    } 
    
  };
  
  const _throw = msg => {
    throw new Error(msg);
  };
  
  module.exports = Validations;