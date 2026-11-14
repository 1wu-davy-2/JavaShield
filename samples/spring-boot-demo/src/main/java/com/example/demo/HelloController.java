package com.example.demo;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {

    private final GreetingService service;

    public HelloController(GreetingService service) {
        this.service = service;
    }

    @GetMapping("/hello")
    public Map<String, Object> hello(@RequestParam(defaultValue = "world") String name) {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("message", service.greet(name));
        body.put("retries", service.retries());
        body.put("salt", service.saltFingerprint());
        return body;
    }

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }
}
