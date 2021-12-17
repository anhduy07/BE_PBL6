package com.example.demo.service;

import com.example.demo.model.Cart;

import java.util.List;

public interface CartService {
    void save(Cart cart);

    List<Cart> getAll();

    Cart finById(Long id);
}
