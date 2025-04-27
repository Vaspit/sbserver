package com.vaspit.sbserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SbserverApplication

fun main(args: Array<String>) {
	runApplication<SbserverApplication>(*args)
}
