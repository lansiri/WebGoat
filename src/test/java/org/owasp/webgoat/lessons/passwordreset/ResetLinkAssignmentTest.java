/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ResetLinkAssignmentTest extends LessonTest {

  @Value("${webwolf.host}")
  private String webWolfHost;

  @Value("${webwolf.port}")
  private String webWolfPort;

  @Autowired private ResourceLoader resourceLoader;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    ResetLinkAssignment.resetLinks.clear();
    ResetLinkAssignment.userToTomResetLink.clear();
    ResetLinkAssignment.usersToTomPassword.clear();
  }

  @Test
  void unboundResetLinkCannotChangeAnotherUsersPassword() {
    String resetLink = "unbound-reset-link";
    ResetLinkAssignment.resetLinks.add(resetLink);

    var modelAndView =
        new ResetLinkAssignment()
            .changePassword(
                passwordChangeForm(resetLink, "new-password"),
                new BeanPropertyBindingResult(new Object(), "form"),
                "attacker");

    Assertions.assertThat(modelAndView.getViewName())
        .isEqualTo("lessons/passwordreset/templates/password_link_not_found.html");
    Assertions.assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey("attacker");
    Assertions.assertThat(ResetLinkAssignment.resetLinks).contains(resetLink);
  }

  @Test
  void ownerBoundResetLinkChangesOnlyItsOwnersPasswordAndIsConsumed() {
    String resetLink = "owner-bound-reset-link";
    ResetLinkAssignment.resetLinks.add(resetLink);
    ResetLinkAssignment.userToTomResetLink.put("owner", resetLink);

    var modelAndView =
        new ResetLinkAssignment()
            .changePassword(
                passwordChangeForm(resetLink, "new-password"),
                new BeanPropertyBindingResult(new Object(), "form"),
                "owner");

    Assertions.assertThat(modelAndView.getViewName())
        .isEqualTo("lessons/passwordreset/templates/success.html");
    Assertions.assertThat(ResetLinkAssignment.usersToTomPassword)
        .containsEntry("owner", "new-password");
    Assertions.assertThat(ResetLinkAssignment.resetLinks).doesNotContain(resetLink);
    Assertions.assertThat(ResetLinkAssignment.userToTomResetLink).doesNotContainKey("owner");
  }

  private PasswordChangeForm passwordChangeForm(String resetLink, String password) {
    PasswordChangeForm form = new PasswordChangeForm();
    form.setResetLink(resetLink);
    form.setPassword(password);
    return form;
  }

  @Test
  void wrongResetLink() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", "test"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutPasswordShouldReturnPasswordForm() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(MockMvcRequestBuilders.post("/PasswordReset/reset/change-password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutLinkShouldReturnPasswordLinkNotFound() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                    .param("password", "new_password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void knownLinkShouldReturnPasswordResetPage() throws Exception {
    // Create a reset link
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", TOM_EMAIL)
                .header(HttpHeaders.HOST, webWolfHost + ":" + webWolfPort))
        .andExpect(status().isOk());
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isNotEmpty();

    // With a known link you should be
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get(
                    "/PasswordReset/reset/reset-password/{link}",
                    ResetLinkAssignment.resetLinks.get(0)))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();

    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }
}
