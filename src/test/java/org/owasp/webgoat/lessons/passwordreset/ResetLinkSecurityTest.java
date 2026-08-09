/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.client.RestTemplate;

class ResetLinkSecurityTest {

  @AfterEach
  void clearState() {
    ResetLinkAssignment.resetLinks.clear();
    ResetLinkAssignment.userToTomResetLink.clear();
    ResetLinkAssignment.usersToTomPassword.clear();
  }

  @Test
  void resetTokenHasTrustedOriginAndCanOnlyBeConsumedOnceByItsOwner() {
    var restTemplate = mock(RestTemplate.class);
    var endpoint =
        new ResetLinkAssignmentForgotPassword(
            restTemplate, "https://webgoat.example/WebGoat/", "http://webwolf:9090/mail");

    endpoint.sendPasswordResetLink(
        ResetLinkAssignment.TOM_EMAIL, mock(HttpServletRequest.class), "owner");

    String resetLink = ResetLinkAssignment.userToTomResetLink.get("owner");
    var mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate)
        .postForEntity(eq("http://webwolf:9090/mail"), mail.capture(), eq(Object.class));
    assertThat(mail.getValue().getContents())
        .contains("https://webgoat.example/WebGoat/PasswordReset/reset/reset-password/" + resetLink);

    var assignment = new ResetLinkAssignment();
    var attackerResult =
        assignment.changePassword(
            form(resetLink, "attacker-password"), bindingResult(), "attacker");
    assertThat(attackerResult.getViewName())
        .isEqualTo("lessons/passwordreset/templates/password_link_not_found.html");
    assertThat(ResetLinkAssignment.resetLinks).contains(resetLink);

    var ownerResult =
        assignment.changePassword(form(resetLink, "owner-password"), bindingResult(), "owner");
    assertThat(ownerResult.getViewName())
        .isEqualTo("lessons/passwordreset/templates/success.html");
    assertThat(assignment.login("owner-password", ResetLinkAssignment.TOM_EMAIL, "owner")
            .assignmentSolved())
        .isTrue();
    assertThat(ResetLinkAssignment.resetLinks).doesNotContain(resetLink);
    assertThat(ResetLinkAssignment.userToTomResetLink).doesNotContainKey("owner");
  }

  private PasswordChangeForm form(String link, String password) {
    var form = new PasswordChangeForm();
    form.setResetLink(link);
    form.setPassword(password);
    return form;
  }

  private BeanPropertyBindingResult bindingResult() {
    return new BeanPropertyBindingResult(new Object(), "form");
  }
}
