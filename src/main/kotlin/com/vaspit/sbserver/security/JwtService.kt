package com.vaspit.sbserver.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.util.*

@Service
class JwtService(
    @Value("JWT_SECRET_BASE64") private val jwtSecret: String
) {

    private val secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret))
    private val accessTokenValidityMs = 15L * 60L * 1000L // 15 min
    val refreshTokenValidityMs = 30L * 24L * 60L * 1000L // 30 days

    fun generateAccessToken(userId: String): String = generateToken(
        userId = userId,
        type = "access",
        expiry = accessTokenValidityMs
    )

    fun generateRefreshToken(userId: String): String = generateToken(
        userId = userId,
        type = "refresh",
        expiry = refreshTokenValidityMs
    )

    private fun generateToken(
        userId: String,
        type: String,
        expiry: Long
    ): String {
        val now = Date()
        val expiryDate = Date(now.time + expiry)

        return Jwts.builder()
            .subject(userId)
            .claim("type", type)
            .issuedAt(now)
            .expiration(expiryDate)
            .signWith(secretKey, Jwts.SIG.HS256)
            .compact()
    }
}
