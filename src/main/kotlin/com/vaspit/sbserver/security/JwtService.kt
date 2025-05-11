package com.vaspit.sbserver.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.util.*

@Service
class JwtService(
    @Value("\${jwtSecret}") private val jwtSecret: String
) {

    private val secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret))
    private val accessTokenValidityMs = 15L * 60L * 1000L // 15 min
    val refreshTokenValidityMs = 30L * 24L * 60L * 60L * 1000L // 30 days

    fun generateAccessToken(userId: String): String = generateToken(
        userId = userId,
        type = ACCESS_TOKEN_TYPE,
        expiry = accessTokenValidityMs
    )

    fun generateRefreshToken(userId: String): String = generateToken(
        userId = userId,
        type = REFRESH_TOKEN_TYPE,
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
            .claim(CLAIM_TYPE, type)
            .issuedAt(now)
            .expiration(expiryDate)
            .signWith(secretKey, Jwts.SIG.HS256)
            .compact()
    }

    fun validateAccessToken(token: String): Boolean {
        val claims = parseAllClaims(token) ?: return false
        val type = claims[CLAIM_TYPE] as? String ?: return false
        return type == ACCESS_TOKEN_TYPE
    }
    fun validateRefreshToken(token: String): Boolean {
        val claims = parseAllClaims(token) ?: return false
        val type = claims[CLAIM_TYPE] as? String ?: return false
        return type == REFRESH_TOKEN_TYPE
    }

    private fun parseAllClaims(token: String): Claims? {
        return try {
            val rawToken = if (token.startsWith(BEARER_PREFIX)) token.removePrefix(BEARER_PREFIX) else token
            Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(rawToken)
                .payload
        } catch (e: Exception) {
            null
        }
    }

    /**
     * @return userId from token as [String]
     * @throws [IllegalArgumentException] if token is invalid
     */
    fun getUserIdFromToken(token: String): String {
        val claims = parseAllClaims(token) ?: throw IllegalArgumentException("Invalid token.")
        return claims.subject
    }

    companion object {
        private const val ACCESS_TOKEN_TYPE = "access"
        const val BEARER_PREFIX = "Bearer "
        private const val CLAIM_TYPE = "type"
        private const val REFRESH_TOKEN_TYPE = "refresh"
    }
}
