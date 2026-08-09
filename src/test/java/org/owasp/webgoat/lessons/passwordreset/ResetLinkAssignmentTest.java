/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
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
  void resetLinkRequestDoesNotCreateUsableLink() throws Exception {
    ResetLinkAssignment.resetLinks.clear();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", "tom@webgoat-cloud.org"))
        .andExpect(status().isOk());
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isEmpty();

    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", "unknown"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();

    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }
}
