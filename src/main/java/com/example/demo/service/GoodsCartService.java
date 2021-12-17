package com.example.demo.service;

import com.example.demo.model.GoodsCart;
import java.util.List;

public interface GoodsCartService {

    void save(GoodsCart goodsCart);
    List<GoodsCart> getAll();
    GoodsCart findByGoodsCart(Long id);
    GoodsCart findByIdGoodsStatus(Long id);
    void deleteById(Long id);
    List<GoodsCart> findGoodsCartByCart_IdCartAndStatusTrue(Long id);
    List<GoodsCart> findAllByStatusTrue(Boolean value);
}
