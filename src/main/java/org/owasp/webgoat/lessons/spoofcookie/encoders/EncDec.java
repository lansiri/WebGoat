/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  private static final byte[] SIGNING_KEY = new byte[32];

  static {
    new SecureRandom().nextBytes(SIGNING_KEY);
  }

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String payload = base64Encode(value.toLowerCase());
    return payload + "." + base64Encode(sign(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String[] parts = encodedValue.split("\\.", -1);
    if (parts.length != 2) {
      throw new IllegalArgumentException("Invalid cookie signature");
    }
    byte[] presented;
    try {
      presented = Base64.getUrlDecoder().decode(parts[1]);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid cookie signature");
    }
    if (!java.security.MessageDigest.isEqual(sign(parts[0]), presented)) {
      throw new IllegalArgumentException("Invalid cookie signature");
    }
    return base64Decode(parts[0]);
  }

  private static byte[] sign(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(SIGNING_KEY, "HmacSHA256"));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to sign cookie", e);
    }
  }

  private static String base64Encode(final String value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getUrlDecoder().decode(value);
    return new String(decoded, StandardCharsets.UTF_8);
  }

  private static String base64Encode(byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }
}
