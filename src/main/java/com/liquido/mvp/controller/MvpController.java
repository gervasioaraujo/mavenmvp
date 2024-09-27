package com.liquido.mvp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MvpController {

    @GetMapping("/mvp/redeban")
    public String index() {
        return "Liquido MPV's Redeban route!";
    }
}
