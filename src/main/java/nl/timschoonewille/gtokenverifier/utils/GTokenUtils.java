package nl.timschoonewille.gtokenverifier.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import nl.timschoonewille.gtokenverifier.exceptions.GoogleCertException;
import nl.timschoonewille.gtokenverifier.models.GoogleCert;
import nl.timschoonewille.gtokenverifier.models.JwtComponents;

public class GTokenUtils {

  private static final String ALGORITHM = "RSA";

  public static RSAPublicKey generatePublicKey(String eValue, String nValue)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    Decoder decoder = Base64.getUrlDecoder();
    var e = new BigInteger(1, decoder.decode(eValue));
    var n = new BigInteger(1, decoder.decode(nValue));
    var keySpec = new RSAPublicKeySpec(n, e);
    KeyFactory publicKeyFactory = KeyFactory.getInstance(ALGORITHM);
    return (RSAPublicKey) publicKeyFactory.generatePublic(keySpec);
  }

  public static String getAttributeFromJson(ObjectMapper objectMapper, String json,
      String attribute) throws JsonProcessingException {
    JsonNode root = objectMapper.readTree(json);
    var jsonAttr = root.get(attribute);
    if (jsonAttr == null) {
      return null;
    }
    String attributeValue = jsonAttr
        .toString();
    return attributeValue.substring(1, attributeValue.length() - 1);

  }

  public static String retreiveKidFromHeader(ObjectMapper objectMapper, JwtComponents jwt)
      throws JsonProcessingException {
    return getAttributeFromJson(objectMapper, jwt.decodedHeader(), "kid");
  }

  public static GoogleCert assertCorrectCert(List<GoogleCert> certs, String kid)
      throws GoogleCertException {
    if (certs == null || certs.isEmpty()) {
      throw new GoogleCertException("No google certs are present.");
    }
    return certs.stream()
        .filter(cert -> cert.kid()
            .equals(kid))
        .findFirst()
        .orElseThrow();

  }
}
