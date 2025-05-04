package com.vaspit.sbserver.security

import com.vaspit.sbserver.database.model.RefreshToken
import com.vaspit.sbserver.database.model.User
import com.vaspit.sbserver.database.repository.RefreshTokenRepository
import com.vaspit.sbserver.database.repository.UserRepository
import com.vaspit.sbserver.utils.BAD_CREDENTIALS_EXCEPTION
import com.vaspit.sbserver.utils.INVALID_REFRESH_TOKEN
import com.vaspit.sbserver.utils.REFRESH_TOKEN_NOT_RECOGNIZED
import org.bson.types.ObjectId
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.MessageDigest
import java.time.Instant
import java.util.*

@Service
class AuthService(
    private val jwtService: JwtService,
    private val userRepository: UserRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val hashEncoder: HashEncoder
) {
    data class TokenPair(
        val accessToken: String,
        val refreshToken: String
    )

    fun register(email: String, password: String): User {
        return userRepository.save(
            User(
                email = email,
                hashedPassword = hashEncoder.encode(password)
            )
        )
    }

    fun login(email: String, password: String): TokenPair {
        val user = userRepository.findByEmail(email) ?: throw BadCredentialsException(BAD_CREDENTIALS_EXCEPTION)

        if (!hashEncoder.matches(password, user.hashedPassword)) {
            throw BadCredentialsException(BAD_CREDENTIALS_EXCEPTION)
        }

        val accessToken = jwtService.generateAccessToken(user.id.toHexString())
        val refreshToken = jwtService.generateRefreshToken(user.id.toHexString())

        storeRefreshToken(user.id, refreshToken)

        return TokenPair(
            accessToken = accessToken,
            refreshToken = refreshToken
        )
    }

    @Transactional
    fun refresh(refreshToken: String): TokenPair {
        if (!jwtService.validateRefreshToken(refreshToken)) {
            throw IllegalArgumentException(INVALID_REFRESH_TOKEN)
        }

        val userId = jwtService.getUserIdFromToken(refreshToken)
        val user = userRepository.findById(ObjectId(userId)).orElseThrow {
            IllegalArgumentException(INVALID_REFRESH_TOKEN)
        }

        val hashedToken = getHashedToken(refreshToken)
        refreshTokenRepository.findByUserIdAndHashedToken(user.id, hashedToken)
            ?: throw IllegalArgumentException(REFRESH_TOKEN_NOT_RECOGNIZED)

        refreshTokenRepository.deleteByUserIdAndHashedToken(user.id, hashedToken)

        val newAccessToken = jwtService.generateAccessToken(userId)
        val newRefreshToken = jwtService.generateRefreshToken(userId)

        storeRefreshToken(user.id, newRefreshToken)

        return TokenPair(
            accessToken = newAccessToken,
            refreshToken = newRefreshToken
        )
    }

    private fun storeRefreshToken(userId: ObjectId, rawToken: String) {
        val hashedToken = getHashedToken(rawToken)
        val expiryMs = jwtService.refreshTokenValidityMs
        val expiresAt = Instant.now().plusMillis(expiryMs)

        refreshTokenRepository.save(
            RefreshToken(
                userId = userId,
                hashedToken = hashedToken,
                expiresAt = expiresAt,
            )
        )
    }

    private fun getHashedToken(rawToken: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashedBytes = digest.digest(rawToken.encodeToByteArray())
        return Base64.getEncoder().encodeToString(hashedBytes)
    }
}
