package nl.timschoonewille.gtokenverifier.models;

import java.time.LocalDateTime;
import java.util.List;

public record CertsWithExpiration(List<GoogleCert> certs, LocalDateTime expiresOn) {

}
