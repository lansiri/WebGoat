/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * @author nbaars
 * @since 11/17/17.
 */
public class CSRFFeedbackTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void postingJsonMessageThroughWebGoatShouldWork() throws Exception {
    mockMvc
        .perform(
            post("/csrf/feedback/message")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"name\": \"Test\", \"email\": \"test1233@dfssdf.de\", \"subject\":"
                        + " \"service\", \"message\":\"dsaffd\"}"))
        .andExpect(status().isOk());
  }

  @Test
  public void csrfAttackDoesNotSolveTheLesson() throws Exception {
    mockMvc
        .perform(
            post("/csrf/feedback/message")
                .contentType(MediaType.TEXT_PLAIN)
                .cookie(new Cookie("JSESSIONID", "test"))
                .header("host", "localhost:8080")
                .header("referer", "http://localhost:8080/csrf")
                .content(
                    "{\"name\": \"Test\", \"email\": \"test1233@dfssdf.de\", \"subject\":"
                        + " \"service\", \"message\":\"dsaffd\"}"))
        .andExpect(status().isOk());
  }

  @Test
  public void validCsrfShapedRequestDoesNotCreateSessionFlag() {
    LessonSession lessonSession = new LessonSession();
    CSRFFeedback feedback = new CSRFFeedback(lessonSession, new ObjectMapper());
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setCookies(new Cookie("JSESSIONID", "test"));
    request.setContentType(MediaType.TEXT_PLAIN_VALUE);
    request.addHeader("Host", "localhost:8080");
    request.addHeader("Referer", "http://localhost:8080/csrf");

    feedback.completed(request, "{\"name\":\"Test\"}");

    assertNull(lessonSession.getValue("csrf-feedback"));
  }
}
