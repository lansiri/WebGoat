/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.hamcrest.core.Is.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CSRFGetFlagTest extends LessonTest {

  @BeforeEach
  void setup() {
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).build();
  }

  @Test
  void forgedOriginCannotReceiveFlag() throws Exception {
    mockMvc
        .perform(
            post("/csrf/basic-get-flag")
                .header("host", "localhost:8080")
                .header("origin", "http://localhost:8080"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.flag").isEmpty());
  }
}
