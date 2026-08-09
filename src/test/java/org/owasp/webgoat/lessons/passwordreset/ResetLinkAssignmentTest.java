/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;

class ResetLinkAssignmentTest extends LessonTest {

  @Value("${webwolf.host}")
  private String webWolfHost;

  @Value("${webwolf.port}")
  private String webWolfPort;

  @Autowired private ResourceLoader resourceLoader;

  @MockBean private RestTemplate restTemplate;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    ResetLinkAssignment.clearResetState();
    when(restTemplate.postForEntity(anyString(), any(PasswordResetEmail.class), eq(Object.class)))
        .thenReturn(ResponseEntity.ok().build());
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

  @Test
  void resetLinkChangesOnlyTheRequestedAccountAndCannotBeReused() throws Exception {
    String ownerEmail = "test@webgoat.org";
    String password = "new-password";

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", ownerEmail))
        .andExpect(status().isOk());
    String resetLink = ResetLinkAssignment.resetLinks.get(0);

    mockMvc
        .perform(
            MockMvcRequestBuilders.get(
                "/PasswordReset/reset/reset-password/{link}", resetLink))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", resetLink)
                .param("password", password))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/success.html"));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", ownerEmail)
                .param("password", password))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", password))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", resetLink)
                .param("password", "replayed-password"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
  }

  @Test
  void passwordResetMailUsesTheConfiguredOriginInsteadOfTheHostHeader() throws Exception {
    ArgumentCaptor<PasswordResetEmail> mailCaptor = ArgumentCaptor.forClass(PasswordResetEmail.class);

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", TOM_EMAIL)
                .header(HttpHeaders.HOST, "attacker.invalid"))
        .andExpect(status().isOk());

    verify(restTemplate).postForEntity(anyString(), mailCaptor.capture(), eq(Object.class));
    PasswordResetEmail mail = mailCaptor.getValue();
    Assertions.assertThat(mail.getRecipient()).isEqualTo("tom");
    Assertions.assertThat(mail.getContents())
        .doesNotContain("attacker.invalid")
        .contains("/PasswordReset/reset/reset-password/");
  }
}
