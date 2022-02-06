package com.example.controller;

import com.example.entity.User;
import com.example.service.UserService;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/admin")
public class AdminController {
    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping()
    public String userList(Model model) {
        model.addAttribute("allUsers", userService.allUsers());
        return "admin";
    }

//    @GetMapping("/get/{userId}")
//    public String  getUser(@PathVariable("userId") Long userId, Model model) {
//        User user = userService.findUserById(userId);
//        System.out.print(1111111);
//        if (user != null)
//            //model.addAttribute("result", user.toString());
//            return user.toString();
//        else model.addAttribute("result", "No such user!");
//        return "dsdfsd";
//    }

    @GetMapping("/delete/{userId}")
    public String  deleteUser(@PathVariable("userId") Long userId, Model model) {
        if (userService.deleteUser(userId))
            model.addAttribute("result", "User#" + userId + " was successfully deleted!");
        else model.addAttribute("result", "No such user!");
        return "admin";
    }
}
