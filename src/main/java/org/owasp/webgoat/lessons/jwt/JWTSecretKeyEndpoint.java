/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  /** Retained for lesson-client compatibility; these values are never used as signing keys. */
  public static final String[] SECRETS = {
    "victory", "business", "available", "shipping", "washington"
  };
  private static final Key JWT_SIGNING_KEY =
      new SecretKeySpec(generateSecret(), SignatureAlgorithm.HS256.getJcaName());
  private static final String WEBGOAT_USER = "WebGoat";
  private static final String TOKEN_ISSUER = "WebGoat Token Builder";
  private static final String TOKEN_AUDIENCE = "webgoat.org";
  private static final String TOKEN_SUBJECT = "tom@webgoat.org";
  private static final String TOKEN_EMAIL = "tom@webgoat.org";
  private static final List<String> TOKEN_ROLES =
      Arrays.asList("Manager", "Project Administrator");
  private static final List<String> expectedClaims =
      List.of("iss", "iat", "exp", "aud", "sub", "username", "Email", "Role");

  private static byte[] generateSecret() {
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    return secret;
  }

  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return issueTrustedToken("Tom");
  }

  /**
   * Server-side identity-provider boundary. This method is deliberately not exposed through HTTP;
   * callers must already be trusted to mint an identity token.
   */
  String issueTrustedToken(String username) {
    Claims claims = Jwts.claims();
    claims.setIssuer(TOKEN_ISSUER);
    claims.setAudience(TOKEN_AUDIENCE);
    claims.setIssuedAt(Calendar.getInstance().getTime());
    claims.setExpiration(Date.from(Instant.now().plusSeconds(60)));
    claims.setSubject(TOKEN_SUBJECT);
    claims.put("username", username);
    claims.put("Email", TOKEN_EMAIL);
    claims.put("Role", TOKEN_ROLES);
    return issueTrustedToken(claims);
  }

  String issueTrustedToken(Claims claims) {
    return Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, JWT_SIGNING_KEY).compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    try {
      Jws<Claims> jwt = Jwts.parser().setSigningKey(JWT_SIGNING_KEY).parseClaimsJws(token);
      Claims claims = jwt.getBody();
      if (!hasExpectedClaims(claims)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      }
      String user = (String) claims.get("username");
      if (WEBGOAT_USER.equalsIgnoreCase(user)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
    } catch (Exception e) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }

  private boolean hasExpectedClaims(Claims claims) {
    return claims.keySet().containsAll(expectedClaims)
        && TOKEN_ISSUER.equals(claims.getIssuer())
        && TOKEN_AUDIENCE.equals(claims.getAudience())
        && TOKEN_SUBJECT.equals(claims.getSubject())
        && TOKEN_EMAIL.equals(claims.get("Email"))
        && TOKEN_ROLES.equals(claims.get("Role"));
  }
}
