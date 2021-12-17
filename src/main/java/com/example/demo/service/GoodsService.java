package com.example.demo.service;

import com.example.demo.model.Goods;

import java.util.List;

public interface GoodsService {
    List<Goods> findAllGoods();
    Goods findById(Long id);
    void deleteById(Long id);
    void save(Goods goods);
    List<Goods> findAllByCategory_IdCategory(Long id);
    List<Goods> findAllByGoodsNameContaining(String name);
}
