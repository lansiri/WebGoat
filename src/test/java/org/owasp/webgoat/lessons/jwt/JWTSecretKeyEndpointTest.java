/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
public class JWTSecretKeyEndpointTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  private Claims createClaims(String username) {
    Claims claims = Jwts.claims();
    claims.put("admin", "true");
    claims.put("user", "Tom");
    claims.setExpiration(Date.from(Instant.now().plus(Duration.ofDays(1))));
    claims.setIssuedAt(Date.from(Instant.now().plus(Duration.ofDays(1))));
    claims.setIssuer("iss");
    claims.setAudience("aud");
    claims.setSubject("sub");
    claims.put("username", username);
    claims.put("Email", "webgoat@webgoat.io");
    claims.put("Role", new String[] {"user"});
    return claims;
  }

  @Test
  public void serverIssuedTokenRetainsNormalFailureResponse() throws Exception {
    String token = new JWTSecretKeyEndpoint().getSecretToken();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(
                    messages.getMessage("jwt-secret-incorrect-user", "default", "Tom"))));
  }

  @Test
  public void oneOfClaimIsMissingShouldNotSolveAssignment() throws Exception {
    Claims claims = createClaims("WebGoat");
    claims.remove("aud");
    String token = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, "wrong_key").compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  public void incorrectUser() throws Exception {
    Claims claims = createClaims("Tom");
    String token = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, "wrong_key").compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  public void incorrectToken() throws Exception {
    Claims claims = createClaims("Tom");
    String token = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, "wrong_password").compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void unsignedToken() throws Exception {
    Claims claims = createClaims("WebGoat");
    String token = Jwts.builder().setClaims(claims).compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void dictionarySecretsCannotForgeWebGoatToken() throws Exception {
    Claims claims = createClaims("WebGoat");
    for (String weakSecret : JWTSecretKeyEndpoint.SECRETS) {
      String token =
          Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS256, weakSecret).compact();

      mockMvc
          .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)))
          .andExpect(
              jsonPath(
                  "$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
    }
  }

  @Test
  void issuedIdentityRequiresEveryBoundClaim() {
    Claims valid = Jwts.claims();
    valid.setIssuer("WebGoat Token Builder");
    valid.setAudience("webgoat.org");
    valid.setSubject("tom@webgoat.org");
    valid.put("username", "Tom");
    valid.put("Email", "tom@webgoat.org");
    valid.put("Role", Arrays.asList("Manager", "Project Administrator"));

    assertThat(JWTSecretKeyEndpoint.isIssuedTokenIdentity(valid), is(true));
    valid.put("username", "WebGoat");
    assertThat(JWTSecretKeyEndpoint.isIssuedTokenIdentity(valid), is(false));
  }

  @Test
  void signingKeyIsNotPubliclyExposed() {
    assertThat(
        Arrays.stream(JWTSecretKeyEndpoint.class.getFields())
            .map(field -> field.getName())
            .anyMatch("JWT_SECRET"::equals),
        is(false));
  }
}
