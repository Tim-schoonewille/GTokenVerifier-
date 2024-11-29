package nl.timschoonewille.gtokenverifier;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import nl.timschoonewille.gtokenverifier.exceptions.GoogleCertException;
import nl.timschoonewille.gtokenverifier.exceptions.InvalidIdTokenException;
import nl.timschoonewille.gtokenverifier.models.GoogleCert;
import nl.timschoonewille.gtokenverifier.models.JwtComponents;
import nl.timschoonewille.gtokenverifier.utils.GTokenUtils;
import nl.timschoonewille.gtokenverifier.utils.GoogleCertsProvider;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

public class GTokenVerifier {

  private final String audience;
  private final ObjectMapper objectMapper;
  private List<GoogleCert> certs;
  private LocalDateTime expiresOn;

  GTokenVerifier(String audience) {
    this.audience = audience;
    objectMapper = new ObjectMapper();
  }


  Map<String, String> decode(String idToken) throws InvalidIdTokenException {
    return decode(idToken);
  }

  Map<String, String> decode(String idToken, String... attributes) throws InvalidIdTokenException {
    return decode(idToken, false, attributes);
  }

  Map<String, String> decode(String idToken, boolean throwExceptionOnInvalidAttribute,
      String... attributes)
      throws InvalidIdTokenException {
    try {
      validateCerts();
      JwtComponents jwtComponents = JwtComponents.fromToken(idToken);
      String kid = GTokenUtils.retreiveKidFromHeader(objectMapper, jwtComponents);
      GoogleCert cert = GTokenUtils.assertCorrectCert(certs, kid);
      RSAPublicKey publicKey = GTokenUtils.generatePublicKey(cert.e(), cert.n());
      if (validateJwt(publicKey, idToken)) {
        return attributes.length == 0
            ? new HashMap<>()
            : getAttributesFromPayload(jwtComponents.decodedPayload(), attributes,
                throwExceptionOnInvalidAttribute);
      } else {
        throw new InvalidIdTokenException("Public key does not match the private key.");
      }
    } catch (Exception e) {
      throw new InvalidIdTokenException("Invalid ID token:\n" + e.getMessage());
    }
  }

  private boolean validateJwt(RSAPublicKey publicKey, String idToken) {
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime()
        .setRequireSubject()
        .setVerificationKey(publicKey)
        .setExpectedAudience(audience)
        .build();
    try {
      jwtConsumer.process(idToken);
      return true;
    } catch (InvalidJwtException e) {
      return false;
    }
  }

  private Map<String, String> getAttributesFromPayload(String payload, String[] attributes,
      boolean throwExceptionOnInvalidAttribute)
      throws Exception {
    Map<String, String> payloadAttributes = new HashMap<>();
    for (String attribute : attributes) {
      try {
        var value = GTokenUtils.getAttributeFromJson(objectMapper, payload, attribute);
        if (value == null) {
          if (throwExceptionOnInvalidAttribute) {
            throw new InvalidIdTokenException(
                "The attribute: %s, is not valid.".formatted(attribute));
          }
          continue;
        }
        payloadAttributes.put(attribute, value);
      } catch (JsonProcessingException e) {
      }
    }
    return payloadAttributes;
  }

  private void validateCerts() throws GoogleCertException {
    if (expiresOn == null || expiresOn.isBefore(LocalDateTime.now())) {
      var certsWithExpiration = GoogleCertsProvider.getCerts();
      expiresOn = certsWithExpiration.expiresOn();
      certs = certsWithExpiration.certs();
    }
  }
}
