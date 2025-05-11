package com.vaspit.sbserver.controllers

import com.vaspit.sbserver.database.model.Note
import com.vaspit.sbserver.database.repository.NoteRepository
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import org.bson.types.ObjectId
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*
import java.time.Instant

@Suppress("UNUSED")
@RestController
@RequestMapping("/notes")
class NotesController(
    private val repository: NoteRepository
) {

    data class NoteRequest(
        val id: String?,
        @field:NotBlank(message = "Title can't be blank")
        val title: String,
        val content: String,
        val color: Long,
    )

    data class NoteResponse(
        val id: String,
        val title: String,
        val content: String,
        val color: Long,
        val createdAt: Instant
    )

    @PostMapping
    fun save(
        @Valid @RequestBody body: NoteRequest
    ): NoteResponse {
        val ownerId = SecurityContextHolder.getContext().authentication.principal as String
        val note = repository.save(
            Note(
                id = body.id?.let { ObjectId(it) } ?: ObjectId.get(),
                title = body.title,
                content = body.content,
                color = body.color,
                createdAt = Instant.now(),
                ownerId = ObjectId(ownerId)
            )
        )

        return note.toNoteResponse()
    }

    @GetMapping
    fun findByOwnerId(): List<NoteResponse> {
        val ownerId = SecurityContextHolder.getContext().authentication.principal as String
        return repository.findByOwnerId(ObjectId(ownerId)).map {
            it.toNoteResponse()
        }
    }

    @DeleteMapping(path = ["/{id}"])
    fun deleteById(
        @PathVariable id: String
    ) {
        val note = repository.findById(ObjectId(id)).orElseThrow {
            IllegalStateException("There is no note with such id: $id")
        }
        val ownerId = SecurityContextHolder.getContext().authentication.principal as String

        if (note.ownerId.toHexString() == ownerId) {
            repository.deleteById(ObjectId(id))
        }
    }

    private fun Note.toNoteResponse() = NoteResponse(
        id = this.id.toHexString(),
        title = this.title,
        content = this.content,
        color = this.color,
        createdAt = this.createdAt
    )
}