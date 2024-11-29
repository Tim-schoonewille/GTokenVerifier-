package nl.timschoonewille.gtokenverifier.exceptions;

public class InvalidIdTokenException extends Exception {

  public InvalidIdTokenException() {
  }

  public InvalidIdTokenException(String message) {
    super(message);
  }
}
