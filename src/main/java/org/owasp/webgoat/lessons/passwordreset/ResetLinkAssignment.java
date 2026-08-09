/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.util.StringUtils.hasText;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
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
  static List<String> resetLinks = new ArrayList<>();
  static Map<String, ResetTarget> resetLinkTargets = new HashMap<>();
  static Map<ResetTarget, String> accountPasswords = new HashMap<>();
  private static final Object RESET_LINK_LOCK = new Object();

  static final String TEMPLATE =
      """
      Hi, you requested a password reset link, please use this <a target='_blank'
       href='%s/PasswordReset/reset/reset-password/%s'>link</a> to reset your
       password.

      If you did not request this password change you can ignore this message.
      If you have any comments or questions, please do not hesitate to reach us at
       support@webgoat-cloud.org

      Kind regards,
      Team WebGoat
      """;

  record ResetTarget(String owner, String email) {}

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam String password, @RequestParam String email, @CurrentUsername String username) {
    if (passwordMatches(username, email, password)) {
      return success(this).build();
    }
    return failed(this).feedback("login_failed").build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(
      @PathVariable(value = "link") String link,
      Model model,
      @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (isOwnedResetLink(link, username)) {
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

  static void registerResetLink(String resetLink, String owner, String email) {
    synchronized (RESET_LINK_LOCK) {
      resetLinks.add(resetLink);
      resetLinkTargets.put(resetLink, new ResetTarget(owner, normalizeEmail(email)));
    }
  }

  static void removeResetLink(String resetLink) {
    synchronized (RESET_LINK_LOCK) {
      resetLinks.remove(resetLink);
      resetLinkTargets.remove(resetLink);
    }
  }

  static void clearResetState() {
    synchronized (RESET_LINK_LOCK) {
      resetLinks.clear();
      resetLinkTargets.clear();
      accountPasswords.clear();
    }
  }

  private static boolean isOwnedResetLink(String resetLink, String username) {
    synchronized (RESET_LINK_LOCK) {
      ResetTarget target = resetLinkTargets.get(resetLink);
      return target != null && target.owner().equals(username) && resetLinks.contains(resetLink);
    }
  }

  private static boolean consumeResetLink(String resetLink, String username, String password) {
    if (!hasText(resetLink)) {
      return false;
    }
    synchronized (RESET_LINK_LOCK) {
      ResetTarget target = resetLinkTargets.get(resetLink);
      if (target == null || !target.owner().equals(username) || !resetLinks.remove(resetLink)) {
        return false;
      }
      accountPasswords.put(target, password);
      resetLinkTargets.remove(resetLink);
      return true;
    }
  }

  private static boolean passwordMatches(String owner, String email, String password) {
    synchronized (RESET_LINK_LOCK) {
      String accountPassword =
          accountPasswords.get(new ResetTarget(owner, normalizeEmail(email)));
      return accountPassword != null && accountPassword.equals(password);
    }
  }

  private static String normalizeEmail(String email) {
    return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
  }
}
