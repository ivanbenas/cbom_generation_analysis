/**
 * @name Cryptographic Algorithm Usage
 * @description Detects usage of cryptographic algorithms in Java code
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id java/crypto/algorithm-usage
 * @tags security cryptography
 */

import java

// Cryptographic algorithm patterns
class CryptoAlgorithm extends MethodCall {
  CryptoAlgorithm() {
    // MessageDigest (hashing)
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    this.getMethod().hasName("getInstance")
    or
    // Mac (Message Authentication Code)
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    this.getMethod().hasName("getInstance")
    or
    // Cipher (encryption/decryption)
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    this.getMethod().hasName("getInstance")
    or
    // KeyStore
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    this.getMethod().hasName("getInstance")
    or
    // SecretKeyFactory
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "SecretKeyFactory") and
    this.getMethod().hasName("getInstance")
    or
    // KeyPairGenerator
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
    this.getMethod().hasName("getInstance")
    or
    // KeyGenerator
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
    this.getMethod().hasName("getInstance")
    or
    // Signature
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "Signature") and
    this.getMethod().hasName("getInstance")
    or
    // CertificateFactory
    this.getMethod().getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    this.getMethod().hasName("getInstance")
  }
  
  string getAlgorithmName() {
    if exists(this.getArgument(0).(StringLiteral).getValue()) then
      result = this.getArgument(0).(StringLiteral).getValue()
    else
      result = "dynamic/unknown"
  }
  
  string getAlgorithmType() {
    if this.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") then
      result = "hash"
    else if this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Mac") then
      result = "mac"
    else if this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") then
      result = "cipher"
    else if this.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") then
      result = "keystore"
    else if this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "SecretKeyFactory") then
      result = "secret-key-factory"
    else if this.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") then
      result = "key-pair-generator"
    else if this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") then
      result = "key-generator"
    else if this.getMethod().getDeclaringType().hasQualifiedName("java.security", "Signature") then
      result = "signature"
    else if this.getMethod().getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") then
      result = "certificate-factory"
    else
      result = "unknown"
  }
}

from CryptoAlgorithm crypto
select 
  crypto,
  "Cryptographic " + crypto.getAlgorithmType() + " algorithm: '" + crypto.getAlgorithmName() + "'",
  crypto.getAlgorithmType(),
  crypto.getAlgorithmName()
