/**
 * @name Key Management Operations
 * @description Detects cryptographic key generation and management
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id java/crypto/key-management
 * @tags security cryptography key-management
 */

import java

class KeyManagementOperation extends MethodCall {
  KeyManagementOperation() {
    // Key generation
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
    this.getMethod().hasName("generateKeyPair")
    or
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
    this.getMethod().hasName("generateKey")
    or
    // KeyStore operations
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    (
      this.getMethod().hasName("load") or
      this.getMethod().hasName("store") or
      this.getMethod().hasName("getKey") or
      this.getMethod().hasName("setKeyEntry")
    )
    or
    // Key agreement
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyAgreement") and
    this.getMethod().hasName("generateSecret")
  }
  
  string getOperationType() {
    if this.getMethod().hasName("generateKeyPair") then
      result = "asymmetric-key-generation"
    else if this.getMethod().hasName("generateKey") then
      result = "symmetric-key-generation"
    else if this.getMethod().hasName("load") then
      result = "keystore-load"
    else if this.getMethod().hasName("store") then
      result = "keystore-store"
    else if this.getMethod().hasName("getKey") then
      result = "key-retrieval"
    else if this.getMethod().hasName("setKeyEntry") then
      result = "key-storage"
    else if this.getMethod().hasName("generateSecret") then
      result = "key-agreement"
    else
      result = "key-operation"
  }
}

from KeyManagementOperation keyOp
select 
  keyOp,
  "Key management operation: " + keyOp.getOperationType()
