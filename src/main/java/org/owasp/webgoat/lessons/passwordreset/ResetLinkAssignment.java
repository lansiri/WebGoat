/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.util.StringUtils.hasText;

import com.google.common.collect.Maps;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
@AssignmentHints({
  "password-reset-hint1",
  "password-reset-hint2",
  "password-reset-hint3",
  "password-reset-hint4",
  "password-reset-hint5",
  "password-reset-hint6"
})
public class ResetLinkAssignment implements AssignmentEndpoint {

  private static final String VIEW_FORMATTER = "lessons/passwordreset/templates/%s.html";
  static final String PASSWORD_TOM_9 =
      "somethingVeryRandomWhichNoOneWillEverTypeInAsPasswordForTom";
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  static final Duration RESET_LINK_LIFETIME = Duration.ofMinutes(15);
  private static final Object RESET_LINK_LOCK = new Object();
  static Map<String, String> userToTomResetLink = new HashMap<>();
  static Map<String, String> usersToTomPassword = Maps.newHashMap();
  static List<String> resetLinks = new ArrayList<>();
  static Map<String, Instant> resetLinkExpirations = new HashMap<>();

  static final String TEMPLATE =
      """
      Hi, you requested a password reset link, please use this <a target='_blank'
       href='http://%s/WebGoat/PasswordReset/reset/reset-password/%s'>link</a> to reset your
       password.

      If you did not request this password change you can ignore this message.
      If you have any comments or questions, please do not hesitate to reach us at
       support@webgoat-cloud.org

      Kind regards,
      Team WebGoat
      """;

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam String password, @RequestParam String email, @CurrentUsername String username) {
    if (TOM_EMAIL.equals(email)) {
      String passwordTom = usersToTomPassword.getOrDefault(username, PASSWORD_TOM_9);
      if (passwordTom.equals(PASSWORD_TOM_9)) {
        return failed(this).feedback("login_failed").build();
      } else if (passwordTom.equals(password)) {
        return success(this).build();
      }
    }
    return failed(this).feedback("login_failed.tom").build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(@PathVariable(value = "link") String link, Model model) {
    ModelAndView modelAndView = new ModelAndView();
    if (isUsableResetLink(link)) {
      PasswordChangeForm form = new PasswordChangeForm();
      form.setResetLink(link);
      model.addAttribute("form", form);
      modelAndView.addObject("form", form);
      modelAndView.setViewName(
          VIEW_FORMATTER.formatted("password_reset")); // Display html page for changing password
    } else {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
  }

  @PostMapping("/PasswordReset/reset/change-password")
  public ModelAndView changePassword(
      @ModelAttribute("form") PasswordChangeForm form,
      BindingResult bindingResult,
      @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (!hasText(form.getPassword())) {
      bindingResult.rejectValue("password", "not.empty");
    }
    if (bindingResult.hasErrors()) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
      return modelAndView;
    }
    if (!consumeResetLink(form.getResetLink(), username, form.getPassword())) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }

  static void registerResetLink(String resetLink) {
    synchronized (RESET_LINK_LOCK) {
      resetLinks.add(resetLink);
      resetLinkExpirations.put(resetLink, Instant.now().plus(RESET_LINK_LIFETIME));
    }
  }

  private static boolean isUsableResetLink(String resetLink) {
    synchronized (RESET_LINK_LOCK) {
      Instant expiresAt = resetLinkExpirations.get(resetLink);
      if (expiresAt == null || !expiresAt.isAfter(Instant.now())) {
        removeResetLink(resetLink);
        return false;
      }
      return resetLinks.contains(resetLink);
    }
  }

  private static boolean consumeResetLink(String resetLink, String username, String password) {
    synchronized (RESET_LINK_LOCK) {
      if (!isUsableResetLink(resetLink)) {
        return false;
      }
      if (checkIfLinkIsFromTom(resetLink, username)) {
        usersToTomPassword.put(username, password);
      }
      removeResetLink(resetLink);
      return true;
    }
  }

  private static void removeResetLink(String resetLink) {
    resetLinks.remove(resetLink);
    resetLinkExpirations.remove(resetLink);
    userToTomResetLink.entrySet().removeIf(entry -> resetLink.equals(entry.getValue()));
  }

  private static boolean checkIfLinkIsFromTom(String resetLinkFromForm, String username) {
    String resetLink = userToTomResetLink.getOrDefault(username, "unknown");
    return resetLink.equals(resetLinkFromForm);
  }
}
