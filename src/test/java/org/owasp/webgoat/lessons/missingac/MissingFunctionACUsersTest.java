/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACUsersTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void userNamedJerryCannotReadLessonUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json")
                .with(user(new WebGoatUser("Jerry", "password", WebGoatUser.ROLE_USER))))
        .andExpect(status().isForbidden());
  }

  @Test
  void applicationAdminCanReadLessonUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json")
                .with(user(new WebGoatUser("administrator", "password", WebGoatUser.ROLE_ADMIN))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username", CoreMatchers.is("Tom")))
        .andExpect(
            jsonPath(
                "$[0].userHash", CoreMatchers.is("Mydnhcy00j2b0m6SjmPz6PUxF9WIeO7tzm665GiZWCo=")))
        .andExpect(jsonPath("$[0].admin", CoreMatchers.is(false)));
  }

  @Test
  void addUser() throws Exception {
    var payload =
        """
        {"username":"newUser","password":"newUser12","admin": "true"}
        """;
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users")
                .header("Content-type", "application/json")
                .content(payload)
                .with(user(new WebGoatUser("administrator", "password", WebGoatUser.ROLE_ADMIN))))
        .andExpect(status().isOk());

    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json")
                .with(user(new WebGoatUser("administrator", "password", WebGoatUser.ROLE_ADMIN))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.size()", is(4)));
  }
}
