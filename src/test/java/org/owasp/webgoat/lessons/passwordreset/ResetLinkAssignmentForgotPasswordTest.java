/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ResetLinkAssignmentForgotPasswordTest {

  @AfterEach
  void clearResetLinks() {
    ResetLinkAssignment.resetLinks.clear();
  }

  @Test
  void doesNotIssueResetLinks() {
    var endpoint = new ResetLinkAssignmentForgotPassword();

    endpoint.sendPasswordResetLink("tom@webgoat-cloud.org", null, "webgoat");

    assertThat(ResetLinkAssignment.resetLinks).isEmpty();
  }
}
