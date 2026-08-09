/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.Key;
import java.time.Instant;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.security.SecureRandom;
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
  private static final String TOKEN_USERNAME = "Tom";
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
    return Jwts.builder()
        .setIssuer(TOKEN_ISSUER)
        .setAudience(TOKEN_AUDIENCE)
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject(TOKEN_SUBJECT)
        .claim("username", TOKEN_USERNAME)
        .claim("Email", TOKEN_EMAIL)
        .claim("Role", TOKEN_ROLES)
        .signWith(SignatureAlgorithm.HS256, JWT_SIGNING_KEY)
        .compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    try {
      Jws<Claims> jwt = Jwts.parser().setSigningKey(JWT_SIGNING_KEY).parseClaimsJws(token);
      Claims claims = jwt.getBody();
      if (!claims.keySet().containsAll(expectedClaims) || !isIssuedTokenIdentity(claims)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      }
      String user = (String) claims.get("username");

      if (WEBGOAT_USER.equalsIgnoreCase(user)) {
        return failed(this).feedback("jwt-invalid-token").build();
      }
      return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
    } catch (Exception e) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }

  static boolean isIssuedTokenIdentity(Claims claims) {
    Object roles = claims.get("Role");
    return TOKEN_ISSUER.equals(claims.getIssuer())
        && TOKEN_AUDIENCE.equals(claims.getAudience())
        && TOKEN_SUBJECT.equals(claims.getSubject())
        && TOKEN_USERNAME.equals(claims.get("username"))
        && TOKEN_EMAIL.equals(claims.get("Email"))
        && TOKEN_ROLES.equals(roles);
  }
}
