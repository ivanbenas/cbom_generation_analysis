/**
 * @name Secure Random Number Generation
 * @description Detects usage of SecureRandom and potential insecure random sources
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id java/crypto/random-generation
 * @tags security cryptography random
 */

import java

class RandomGeneration extends MethodCall {
  RandomGeneration() {
    // SecureRandom
    this.getMethod().getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    (
      this.getMethod().hasName("getInstance") or
      this.getMethod().hasName("nextBytes")
    )
    or
    // Insecure Random (should flag)
    this.getMethod().getDeclaringType().hasQualifiedName("java.util", "Random") and
    this.getMethod().hasName("nextBytes")
  }
  
  string getRandomType() {
    if this.getMethod().getDeclaringType().hasQualifiedName("java.security", "SecureRandom") then
      result = "SecureRandom"
    else if this.getMethod().getDeclaringType().hasQualifiedName("java.util", "Random") then
      result = "java.util.Random (INSECURE)"
    else
      result = "unknown"
  }
  
  string getAlgorithm() {
    if this.getMethod().hasName("getInstance") and exists(this.getArgument(0)) then
      result = this.getArgument(0).(StringLiteral).getValue()
    else
      result = "default"
  }
  
  string getMessage() {
    if this.getAlgorithm() != "default" then
      result = "Random number generation using " + this.getRandomType() + " (algorithm: " + this.getAlgorithm() + ")"
    else
      result = "Random number generation using " + this.getRandomType()
  }
}

from RandomGeneration rand
select 
  rand,
  rand.getMessage()
