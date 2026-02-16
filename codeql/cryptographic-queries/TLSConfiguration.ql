/**
 * @name TLS/SSL Configuration Detection
 * @description Detects TLS/SSL protocol configurations
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id java/crypto/tls-configuration
 * @tags security cryptography tls
 */

import java

class TLSConfiguration extends Expr {
  TLSConfiguration() {
    // SSLContext.getInstance()
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") and
      mc.getMethod().hasName("getInstance") and
      this = mc
    )
    or
    // SSLEngine.setEnabledProtocols
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLEngine") and
      mc.getMethod().hasName("setEnabledProtocols") and
      this = mc
    )
    or
    // SSLParameters.setProtocols
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLParameters") and
      mc.getMethod().hasName("setProtocols") and
      this = mc
    )
    or
    // HttpsURLConnection
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and
      mc.getMethod().hasName("setSSLSocketFactory") and
      this = mc
    )
  }
  
  string getProtocol() {
    if this instanceof MethodCall then
      exists(MethodCall mc | mc = this |
        if exists(mc.getArgument(0).(StringLiteral).getValue()) then
          result = mc.getArgument(0).(StringLiteral).getValue()
        else
          result = "dynamic/unknown"
      )
    else
      result = "unknown"
  }
  
  string getConfigurationType() {
    if this.(MethodCall).getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") then
      result = "SSLContext"
    else if this.(MethodCall).getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLEngine") then
      result = "SSLEngine"
    else if this.(MethodCall).getMethod().getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLParameters") then
      result = "SSLParameters"
    else
      result = "TLS/SSL Configuration"
  }
}

from TLSConfiguration tls
select 
  tls,
  "TLS/SSL " + tls.getConfigurationType() + " configuration: '" + tls.getProtocol() + "'"
