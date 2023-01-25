script "otp"

/**
* Generate a counter-based One-Time Password
* @param pKey - the key used as seed for password generation
* @param pCounter - the counter value to be used to generate the password. This should be stored for each user and incremented on each request.
*
* @return - the one time password (6 character string, all numerical)
*/
function otp.hotp.gen pKey, pCounter
     local tDigest, tH, tOffset, tValue
     if pCounter is not a number then put 0 into pCounter
     
     put _bytePad(pCounter)
     put _hmac("SHA-1",_bytePad(pCounter),pKey) into tDigest
     
     get binaryDecode("H*",tDigest,tH)
     
     put _hexToByteString(tH) into tValue
     
     // Truncate per https://www.ietf.org/rfc/rfc4226.txt section 5.4
     put charToNum(char -1 of tValue) bitAnd 15 into tOffset
     put ((charToNum(char (tOffset + 1) of tValue) bitAnd 127) * 16777216) \
           bitOr ((charToNum(char (tOffset + 2) of tValue) bitAnd 255) * 65536) \
           bitOr ((charToNum(char (tOffset + 3) of tValue) bitAnd 255) * 256) \
           bitOr ((charToNum(char (tOffset + 4) of tValue) bitAnd 255)) into tValue
     put tValue mod 1000000 into tValue
     repeat for 6 - length(tValue) times
          put "0" before tValue
     end repeat
     return tValue
end otp.hotp.gen


/**
* Check a counter-based One-Time Password
* @param pToken - the Password to validate 
* @param pKey - the key for the one time password (used as seed for password generation)
* @param pWindow - the allowed margin for the counter value - the function will check pWindow number of passwords before/after pCounter. Default: 50
* @param pCounter - the counter value to be checked against. This should be stored for each user and incremented on each request. Default: 0
*
* @return - empty if failed, step (difference between client and server) on success
*/
function otp.hotp.verify pToken, pKey, pCounter, pWindow
     if pWindow is not a number then put 50 into pWindow
     if pCounter is not a number then put 0 into pCounter
     
     // loop through from C-W to C + W to determine if there is
     // a correct code
     repeat with x = pCounter - pWindow to pCounter + pWindow
          if otp.hotp.gen(pKey,x) = pToken then return x - pCounter
     end repeat
     
     // NO MATCHING PASSWORDS
     return empty
end otp.hotp.verify


/**
* Generate a time-based One-Time Password
* @param pKey - the key used as seed for password generation
* @param pTimestep - the time step in seconds to be used as a counter to generate the password. Must be the same for every request. Default: 30
*
* @return - the one time password (6 character string, all numerical)
*/
function otp.totp.gen pKey, pTimestep
     local tCounter, tTime
     if pTimestep is not a number then put 30 into pTimestep
     
     put the seconds into tTime
     
     put floor(tTime / pTimestep) into tCounter
     return otp.hotp.gen(pKey, tCounter)
end otp.totp.gen


/**
* Check a time-based One-Time Password
* @param pToken - the Password to validate 
* @param pKey - the key for the one time password (used as seed for password generation)
* @param pWindow - the allowed margin for the counter value - the function will check pWindow number of passwords before/after the time. Default: 6
* @param pTimestep - the time step in seconds to be used as a counter to generate the password. Must be the same for every request. Default: 30
*
* @return - empty if failed, step (difference between client and server) on success
*/
function otp.totp.verify pToken, pKey, pTimestep, pWindow
     local tCounter, tTime
     if pWindow is not a number then put 6 into pWindow
     if pTimestep is not a number then put 30 into pTimestep
     
     put the seconds into tTime
     
     put floor(tTime / pTimestep) into tCounter
     return otp.hotp.verify(pToken, pKey, tCounter, pWindow)
end otp.totp.verify


private function _hmac pHash, pMsg, pKey
     local tIPad, tOPad
     if length(pKey) > 64 then put messageDigest(pKey,pHash) into pKey
     repeat for (64 - length(pKey)) times
          put null after pKey
     end repeat
     repeat for each byte c in pKey
          put numtobyte(bytetonum(c) bitXor 92) after tOPad -- 0x5c
          put numtobyte(bytetonum(c) bitXor 54) after tIPad -- 0x36
     end repeat
     return messageDigest(tOPad & messageDigest(tIPad & pMsg,pHash),pHash)
end _hmac


private function _bytePad pInput
     local tRV
     repeat for 8 times
          put numToChar(pInput bitand 255) before tRV;
          put floor(pInput/256) into pInput
     end repeat
     return tRV
end _bytePad


private function _hexToByteString pInput
     local tRV
     repeat with x = 1 to length(pInput) step 2
          put binaryEncode("H*",char x to (x+1) of pInput) after tRV
     end repeat
     return tRV
end _hexToByteString