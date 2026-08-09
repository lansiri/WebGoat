/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.util.UUID;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * @author Angel Olle Blazquez
 */

// weak id value and mechanism

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private final Map<String, String> sessions = new ConcurrentHashMap<>();
  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> UUID.randomUUID().toString();
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public Authentication authenticate(Authentication authentication) {
    return authenticate(authentication, null);
  }

  public Authentication authenticate(Authentication authentication, String sessionId) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && StringUtils.isNotEmpty(sessionId)
        && sessionId.equals(sessions.get(authentication.getId()))) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    return authentication;
  }

  protected void registerAuthenticatedSession(String token, String ownerSessionId) {
    if (StringUtils.isNotEmpty(token) && StringUtils.isNotEmpty(ownerSessionId)) {
      sessions.put(token, ownerSessionId);
    }
  }

  protected int getSessionsSize() {
    return sessions.size();
  }
}
