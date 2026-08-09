/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * @author Angel Olle Blazquez
 */

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private final Map<String, String> sessions = new ConcurrentHashMap<>();
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
      };
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public Authentication authenticate(Authentication authentication) {
    return authenticate(authentication, null);
  }

  /**
   * A hijack cookie is a bearer credential only within the HTTP session that created it. There is
   * deliberately no automatic authenticated session creation in this lesson endpoint.
   */
  public Authentication authenticate(Authentication authentication, String ownerSessionId) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && ownerSessionId != null
        && ownerSessionId.equals(sessions.get(authentication.getId()))) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    return authentication;
  }

  protected boolean addSession(String sessionId, String ownerSessionId) {
    return sessions.putIfAbsent(sessionId, ownerSessionId) == null;
  }

  protected int getSessionsSize() {
    return sessions.size();
  }
}
