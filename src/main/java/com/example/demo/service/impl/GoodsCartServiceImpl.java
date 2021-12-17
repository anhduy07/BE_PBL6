package com.example.demo.service.impl;

import com.example.demo.model.GoodsCart;
import com.example.demo.repository.GoodsCartRepository;
import com.example.demo.service.GoodsCartService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GoodsCartServiceImpl implements GoodsCartService {
    @Autowired
    GoodsCartRepository goodsCartRepository;

    @Override
    public void save(GoodsCart goodsCart) {
        goodsCartRepository.save(goodsCart);
    }

    @Override
    public List<GoodsCart> getAll() {
        return goodsCartRepository.findAll();
    }

    @Override
    public GoodsCart findByGoodsCart(Long id) {
        return goodsCartRepository.findById(id).orElse(null);
    }

    @Override
    public GoodsCart findByIdGoodsStatus(Long id) {
        return goodsCartRepository.findByIdGoods(id);
    }

    @Override
    public void deleteById(Long id) {
        goodsCartRepository.deleteById(id);
    }

    @Override
    public List<GoodsCart> findGoodsCartByCart_IdCartAndStatusTrue(Long id) {
        return goodsCartRepository.findGoodsCartByCart_IdCartAndStatusTrue(id);
    }

    @Override
    public List<GoodsCart> findAllByStatusTrue(Boolean value) {
        return goodsCartRepository.findAllByStatusTrue(value);
    }

}
