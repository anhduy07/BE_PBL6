package com.example.demo.service.impl;

import com.example.demo.model.Goods;
import com.example.demo.repository.GoodsRepository;
import com.example.demo.service.GoodsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GoodsServiceImpl implements GoodsService {
    @Autowired
    GoodsRepository goodsRepository;

    @Override
    public List<Goods> findAllGoods() {
        return goodsRepository.findAll();
    }

    @Override
    public Goods findById(Long id) {
        return goodsRepository.findById(id).orElse(null);
    }

    @Override
    public void deleteById(Long id) {
        goodsRepository.deleteById(id);
    }

    @Override
    public void save(Goods goods) {
        goodsRepository.save(goods);
    }

    @Override
    public List<Goods> findAllByCategory_IdCategory(Long id) {
        return goodsRepository.findAllByCategory_IdCategory(id);
    }

    @Override
    public List<Goods> findAllByGoodsNameContaining(String name) {
        return goodsRepository.findAllByGoodsNameContaining(name);
    }
}
