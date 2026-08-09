/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.time.Instant;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
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
    ResetLinkAssignment.resetLinkExpirations.clear();
    ResetLinkAssignment.userToTomResetLink.clear();
    ResetLinkAssignment.usersToTomPassword.clear();
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
    Assertions.assertThat(ResetLinkAssignment.resetLinkExpirations)
        .containsKey(ResetLinkAssignment.resetLinks.get(0));

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

  @Test
  void expiredLinkIsRejectedByGetAndCleanedUp() throws Exception {
    String link = "expired-link";
    ResetLinkAssignment.registerResetLink(link);
    ResetLinkAssignment.userToTomResetLink.put("test", link);
    ResetLinkAssignment.resetLinkExpirations.put(link, Instant.now().minusSeconds(1));

    mockMvc
        .perform(MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", link))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));

    assertResetLinkIsFullyRemoved(link);
  }

  @Test
  void expiredLinkCannotChangePassword() throws Exception {
    String link = "expired-link";
    ResetLinkAssignment.registerResetLink(link);
    ResetLinkAssignment.userToTomResetLink.put("test", link);
    ResetLinkAssignment.resetLinkExpirations.put(link, Instant.now().minusSeconds(1));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", link)
                .param("password", "new-password"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));

    Assertions.assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey("test");
    assertResetLinkIsFullyRemoved(link);
  }

  @Test
  void freshOwnedLinkChangesPasswordOnceAndCompletes() throws Exception {
    String link = "fresh-link";
    ResetLinkAssignment.registerResetLink(link);
    ResetLinkAssignment.userToTomResetLink.put("test", link);

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", link)
                .param("password", "new-password"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/success.html"));

    assertResetLinkIsFullyRemoved(link);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", link)
                .param("password", "another-password"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "new-password"))
        .andExpect(status().isOk())
        .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  void wrongCurrentUserOrPasswordCannotCompleteReset() throws Exception {
    ResetLinkAssignment.usersToTomPassword.put("owner", "new-password");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "new-password"))
        .andExpect(status().isOk())
        .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.lessonCompleted", is(false)));

    ResetLinkAssignment.usersToTomPassword.put("test", "new-password");
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "wrong-password"))
        .andExpect(status().isOk())
        .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.lessonCompleted", is(false)));
  }

  private void assertResetLinkIsFullyRemoved(String link) {
    Assertions.assertThat(ResetLinkAssignment.resetLinks).doesNotContain(link);
    Assertions.assertThat(ResetLinkAssignment.resetLinkExpirations).doesNotContainKey(link);
    Assertions.assertThat(ResetLinkAssignment.userToTomResetLink).doesNotContainValue(link);
  }
}
