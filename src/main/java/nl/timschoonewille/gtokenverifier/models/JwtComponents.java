package nl.timschoonewille.gtokenverifier.models;

import java.util.Base64;
import java.util.Base64.Decoder;

public record JwtComponents(String header, String payload, String signature, String decodedHeader,
                            String decodedPayload, String decodedSignature) {


  public static JwtComponents fromToken(String jwtToken) {
    Decoder decoder = Base64.getUrlDecoder();
    String[] parts = jwtToken.split("\\.");
    var header = parts[0];
    var payload = parts[1];
    var signature = parts[2];
    var decodedHeader = new String(decoder.decode(header));
    var decodedPayload = new String(decoder.decode(payload));
    var decodedSignature = new String(decoder.decode(signature));
    return new JwtComponents(header, payload, signature, decodedHeader, decodedPayload,
        decodedSignature);
  }
}
