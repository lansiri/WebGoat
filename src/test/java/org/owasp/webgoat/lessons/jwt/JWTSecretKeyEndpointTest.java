/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Arrays;
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

  @Test
  public void trustedWebGoatTokenCompletesAssignment() throws Exception {
    String token = new JWTSecretKeyEndpoint().issueTrustedToken("WebGoat");

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void serverIssuedTomTokenPreservesNormalFailure() throws Exception {
    String token = new JWTSecretKeyEndpoint().getSecretToken();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(
                    messages.getMessage("jwt-secret-incorrect-user", "default", "Tom"))));
  }

  @Test
  public void dictionarySecretsCannotForgeWebGoatToken() throws Exception {
    for (String weakSecret : JWTSecretKeyEndpoint.SECRETS) {
      String token =
          Jwts.builder()
              .setIssuer("WebGoat Token Builder")
              .setAudience("webgoat.org")
              .setSubject("tom@webgoat.org")
              .claim("username", "WebGoat")
              .claim("Email", "tom@webgoat.org")
              .claim("Role", Arrays.asList("Manager", "Project Administrator"))
              .signWith(SignatureAlgorithm.HS256, weakSecret)
              .compact();

      mockMvc
          .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(false)))
          .andExpect(
              jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
    }
  }

  @Test
  public void missingClaimsCannotCompleteAssignment() throws Exception {
    Claims claims = Jwts.claims();
    claims.setIssuer("WebGoat Token Builder");
    claims.setSubject("tom@webgoat.org");
    claims.put("username", "WebGoat");
    claims.put("Email", "tom@webgoat.org");
    claims.put("Role", Arrays.asList("Manager", "Project Administrator"));
    String token = new JWTSecretKeyEndpoint().issueTrustedToken(claims);

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath(
                "$.feedback", CoreMatchers.is(messages.getMessage("jwt-secret-claims-missing"))));
  }
}
