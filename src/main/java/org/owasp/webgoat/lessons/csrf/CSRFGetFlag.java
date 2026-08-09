/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.security.SecureRandom;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    String host = req.getHeader("host");
    String origin = req.getHeader("origin");

    if (host != null && ("http://" + host).equals(origin)) {
      userSessionData.setValue("csrf-get-success", new SecureRandom().nextInt());
      response.put("success", true);
      response.put("message", "Request origin validated");
      response.put("flag", userSessionData.getValue("csrf-get-success"));
    } else {
      response.put("success", false);
      response.put("message", "Cross-origin request rejected");
      response.put("flag", null);
    }

    return response;
  }
}
