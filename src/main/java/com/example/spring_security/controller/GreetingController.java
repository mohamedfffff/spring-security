package com.example.spring_security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/greeting")
public class GreetingController {

    @GetMapping()
    public ResponseEntity<String> sayHi(){
        return ResponseEntity.ok("sup my guy");
    }

    @GetMapping("/bye")
    public ResponseEntity<String> sayBye(){
        return ResponseEntity.ok("bye my guy");
    }
}
