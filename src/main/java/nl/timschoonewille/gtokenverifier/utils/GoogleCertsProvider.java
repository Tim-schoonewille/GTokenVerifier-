package nl.timschoonewille.gtokenverifier.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.List;
import nl.timschoonewille.gtokenverifier.exceptions.GoogleCertException;
import nl.timschoonewille.gtokenverifier.models.CertResponse;
import nl.timschoonewille.gtokenverifier.models.CertsWithExpiration;
import nl.timschoonewille.gtokenverifier.models.GoogleCert;


public class GoogleCertsProvider {

  private static final String CERT_URL = "https://www.googleapis.com/oauth2/v3/certs";

  public static CertsWithExpiration getCerts() throws GoogleCertException {
    CertResponse response = getCertsResponse();
    List<GoogleCert> certs = convertJsonToObject(response.rawCerts());
    return new CertsWithExpiration(certs, response.expiresAt());
  }

  private static CertResponse getCertsResponse() throws GoogleCertException {
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder(URI.create(CERT_URL))
        .GET()
        .build();
    try {
      HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
      if (response.statusCode() == 200) {
        var certResponse = CertResponse.create(response.body(),
            extractCacheDurationFromHeader(response.headers()));
        return certResponse;
      } else {
        throw new GoogleCertException("");
      }
    } catch (IOException | InterruptedException e) {

      throw new GoogleCertException(
          "Can't fetch the google certs. Please check if the following is still active: %s%n".formatted(
              CERT_URL));
    }
  }

  private static List<GoogleCert> convertJsonToObject(String json) throws GoogleCertException {
    ObjectMapper objectMapper = new ObjectMapper();

    try {
      JsonNode rawKeys = objectMapper.readTree(json)
          .get("keys");
      return objectMapper.readValue(rawKeys.toString(), new TypeReference<List<GoogleCert>>() {
      });

    } catch (JsonProcessingException e) {
      throw new GoogleCertException("Can't convert JSON to GoogleCert object");
    }
  }

  private static int extractCacheDurationFromHeader(HttpHeaders headers)
      throws GoogleCertException {
    var cacheControl = headers.allValues("cache-control");
    var maxAge = cacheControl.get(0)
        .split(",")[1];
    var age = maxAge.split("=")[1];
    return Integer.parseInt(age);
  }
}
