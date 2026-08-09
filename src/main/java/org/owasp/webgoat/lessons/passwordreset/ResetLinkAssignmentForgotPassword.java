/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatUrl;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatUrl) {
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatUrl = webGoatUrl.replaceAll("/+$", "");
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, @CurrentUsername String username) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.registerResetLink(resetLink, username, email);
    try {
      sendMailToUser(email, webGoatUrl, resetLink);
    } catch (Exception e) {
      ResetLinkAssignment.removeResetLink(resetLink);
      return failed(this).output("E-mail can't be send. please try again.").build();
    }

    return failed(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String origin, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, origin, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }
}
