package ma.fstt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

  public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

  public void validateToken(final String token) {
    try {
      Claims claims = Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();

      // Check expiration
      Date expirationDate = claims.getExpiration();
      if (expirationDate != null && expirationDate.before(new Date())) {
        throw new ExpiredJwtException(null, null, "Token has expired", null);
      }
    } catch (ExpiredJwtException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Invalid token", e);
    }
  }

  private Key getSignKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
