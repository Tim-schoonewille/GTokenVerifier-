package nl.timschoonewille.gtokenverifier.models;

import java.time.LocalDateTime;
import nl.timschoonewille.gtokenverifier.exceptions.GoogleCertException;

public record CertResponse(String rawCerts, LocalDateTime expiresAt) {

  public static CertResponse create(String rawCerts, int cacheDuration)
      throws GoogleCertException {
    var now = LocalDateTime.now();
    var expiresAt = now.plusSeconds(cacheDuration);
    if (expiresAt.isBefore(now)) {
      throw new GoogleCertException(
          "Cache expiration is invalid: now: %s, expiresAt: %s".formatted(now, expiresAt));
    }
    return new CertResponse(rawCerts, expiresAt);
  }
}
