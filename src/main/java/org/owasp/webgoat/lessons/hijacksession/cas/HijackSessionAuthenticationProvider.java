/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoublePredicate;
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

  private final Queue<SessionGrant> sessions = new LinkedList<>();
  protected static final int MAX_SESSIONS = 50;
  private static final Duration SESSION_LIFETIME = Duration.ofMinutes(5);
  private final Clock clock;

  private static final DoublePredicate PROBABILITY_DOUBLE_PREDICATE = pr -> pr < 0.75;
  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> UUID.randomUUID().toString();
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  public HijackSessionAuthenticationProvider() {
    this(Clock.systemUTC());
  }

  HijackSessionAuthenticationProvider(Clock clock) {
    this.clock = clock;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && hasActiveSession(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    authorizedUserAutoLogin();

    return authentication;
  }

  protected void authorizedUserAutoLogin() {
    if (!PROBABILITY_DOUBLE_PREDICATE.test(ThreadLocalRandom.current().nextDouble())) {
      Authentication authentication = AUTHENTICATION_SUPPLIER.get();
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected boolean addSession(String sessionId) {
    removeExpiredSessions();
    if (sessions.size() >= MAX_SESSIONS) {
      sessions.remove();
    }
    return sessions.add(new SessionGrant(sessionId, clock.instant().plus(SESSION_LIFETIME)));
  }

  protected int getSessionsSize() {
    return sessions.size();
  }

  private boolean hasActiveSession(String sessionId) {
    removeExpiredSessions();
    return sessions.stream().anyMatch(session -> session.id().equals(sessionId));
  }

  private void removeExpiredSessions() {
    Instant now = clock.instant();
    sessions.removeIf(session -> !session.expiresAt().isAfter(now));
  }

  private record SessionGrant(String id, Instant expiresAt) {}
}
