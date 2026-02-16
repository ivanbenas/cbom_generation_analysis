/**
 * @name Weak Cryptographic Algorithms
 * @description Detects usage of weak or deprecated cryptographic algorithms
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id java/crypto/weak-algorithm
 * @tags security cryptography external/cwe/cwe-327
 */

import java

class WeakCryptoAlgorithm extends MethodCall {
  WeakCryptoAlgorithm() {
    // Weak hash algorithms
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    this.getMethod().hasName("getInstance") and
    exists(StringLiteral algo | algo = this.getArgument(0) |
      algo.getValue().regexpMatch("(?i).*(md5|sha1|sha-1).*")
    )
    or
    // Weak symmetric encryption
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    this.getMethod().hasName("getInstance") and
    exists(StringLiteral algo | algo = this.getArgument(0) |
      algo.getValue().regexpMatch("(?i).*(des|3des|tripledes|rc4|rc2|blowfish).*")
    )
    or
    // Weak MAC algorithms
    this.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    this.getMethod().hasName("getInstance") and
    exists(StringLiteral algo | algo = this.getArgument(0) |
      algo.getValue().regexpMatch("(?i).*(hmacmd5|hmacsha1).*")
    )
  }
  
  string getWeakAlgorithm() {
    if exists(this.getArgument(0).(StringLiteral).getValue()) then
      result = this.getArgument(0).(StringLiteral).getValue()
    else
      result = "unknown"
  }
  
  string getWeaknessReason() {
    if this.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*md5.*") then
      result = "MD5 is cryptographically broken and unsuitable for further use"
    else if this.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*(sha1|sha-1).*") then
      result = "SHA-1 is deprecated and considered weak"
    else if this.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*(des|3des|tripledes).*") then
      result = "DES/3DES uses small key sizes and is vulnerable to brute-force attacks"
    else if this.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*rc4.*") then
      result = "RC4 has multiple vulnerabilities and is prohibited in TLS"
    else if this.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*rc2.*") then
      result = "RC2 is an obsolete algorithm with small block size"
    else if this.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*blowfish.*") then
      result = "Blowfish uses 64-bit blocks, vulnerable to birthday attacks"
    else
      result = "Weak cryptographic algorithm detected"
  }
}

from WeakCryptoAlgorithm weak
select 
  weak,
  "Weak cryptographic algorithm '" + weak.getWeakAlgorithm() + "': " + weak.getWeaknessReason()
