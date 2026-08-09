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
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.validation.BeanPropertyBindingResult;
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
    ResetLinkAssignment.resetLinks.clear();
    ResetLinkAssignment.resetLinkRecipients.clear();
    ResetLinkAssignment.userToTomResetLink.clear();
    ResetLinkAssignment.usersToTomPassword.clear();
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void resetLifecycleBindsTomRecipientAndRejectsForeignUse() {
    var mail = Mockito.mock(org.springframework.web.client.RestTemplate.class);
    var forgot =
        new ResetLinkAssignmentForgotPassword(
            mail, "wolf", "9090", "http://wolf", "http://mail", "https://trusted.example/WebGoat/");
    forgot.sendPasswordResetLink(TOM_EMAIL, Mockito.mock(jakarta.servlet.http.HttpServletRequest.class), "attacker");
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isEmpty();

    forgot.sendPasswordResetLink(TOM_EMAIL, Mockito.mock(jakarta.servlet.http.HttpServletRequest.class), "tom");
    String link = ResetLinkAssignment.resetLinks.getFirst();
    ArgumentCaptor<PasswordResetEmail> email = ArgumentCaptor.forClass(PasswordResetEmail.class);
    Mockito.verify(mail).postForEntity(Mockito.eq("http://mail"), email.capture(), Mockito.eq(Object.class));
    Assertions.assertThat(email.getValue().getContents()).contains("https://trusted.example/WebGoat/PasswordReset/reset/reset-password/" + link);

    var form = new org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm();
    form.setResetLink(link);
    form.setPassword("secret1");
    var assignment = new ResetLinkAssignment();
    assignment.changePassword(form, new BeanPropertyBindingResult(form, "form"), "attacker");
    Assertions.assertThat(ResetLinkAssignment.resetLinks).contains(link);
    assignment.changePassword(form, new BeanPropertyBindingResult(form, "form"), "tom");
    Assertions.assertThat(ResetLinkAssignment.resetLinks).doesNotContain(link);
    Assertions.assertThat(ResetLinkAssignment.usersToTomPassword).containsEntry("tom", "secret1");
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
                .param("email", "test@webgoat-cloud.org")
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
