/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

class ResetLinkTrustedOriginTest {

  @AfterEach
  void clearResetLinks() {
    ResetLinkAssignment.resetLinks.clear();
  }

  @Test
  void resetMailUsesConfiguredWebGoatOriginInsteadOfRequestHost() {
    var restTemplate = mock(RestTemplate.class);
    var request = mock(HttpServletRequest.class);
    when(request.getHeader(HttpHeaders.HOST)).thenReturn("attacker.example");
    var endpoint =
        new ResetLinkAssignmentForgotPassword(
            restTemplate, "https://webgoat.example/WebGoat/", "http://webwolf:9090/mail");

    endpoint.sendPasswordResetLink("tom@webgoat-cloud.org", request, "webgoat");

    var mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate)
        .postForEntity(eq("http://webwolf:9090/mail"), mail.capture(), eq(Object.class));
    assertThat(mail.getValue().getContents())
        .contains("https://webgoat.example/WebGoat/PasswordReset/reset/reset-password/")
        .doesNotContain("attacker.example");
  }
}
