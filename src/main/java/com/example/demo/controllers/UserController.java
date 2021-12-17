package com.example.demo.controllers;

import com.example.demo.model.User;
import com.example.demo.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RestController
@CrossOrigin("*")
@RequestMapping("/user")
public class UserController {

    @Autowired
    GoodsCartService goodsCartService;

    @Autowired
    CartService cartService;

    @Autowired
    UserService userService;

    @Autowired
    BillService billService;

    @Autowired
    GoodsService goodsService;

    @GetMapping("/getAll")
    public ResponseEntity<List<User>> getAll(){
        List<User> list = userService.findAllByStatusTrueAndRole_IdRole(2L);
        if(list.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(list, HttpStatus.OK);
    }
    @PatchMapping("/edit/{idUser}")
    public ResponseEntity<Void> editUser(@PathVariable Long idUser, @RequestBody User user) {
        User userNew = userService.findById(idUser);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } else {
            userNew.setUsername(user.getUsername());
            userNew.setFullName(user.getFullName());
            userNew.setPhoneNumber(user.getPhoneNumber());
            userNew.setAddress(user.getAddress());
            userNew.setEmail(user.getEmail());
            userNew.setImage(user.getImage());
            userService.save(userNew);
            return new ResponseEntity<>(HttpStatus.OK);
        }
    }
    @GetMapping("/userLock/{id}")
    public ResponseEntity<Void> userLock(@PathVariable("id") Long idUser){
        User user = userService.findById(idUser);
        if(user == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        user.setStatus(false);
        userService.save(user);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
