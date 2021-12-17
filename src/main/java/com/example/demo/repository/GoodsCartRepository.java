package com.example.demo.repository;

import com.example.demo.model.GoodsCart;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface GoodsCartRepository extends JpaRepository<GoodsCart,Long> {
    String BY_ID_GOODS = "select* from goods_cart " + "where id_goods = ?1 and `status` = true";
    String ALL_GOODS_CART = "select* from goods_cart " + "where `status` = true";

    String BY_STATUS = "select*\n" +
            "from goods_cart\n" +
            "where id_cart = ?1 and `status` = true";

    @Query(value = BY_ID_GOODS, nativeQuery = true)
    GoodsCart findByIdGoods(Long id);

    @Query(value = BY_STATUS, nativeQuery = true)
    List<GoodsCart> findGoodsCartByCart_IdCartAndStatusTrue(Long id);

    @Query(value = ALL_GOODS_CART, nativeQuery = true)
    List<GoodsCart> findAllByStatusTrue(Boolean value);
}
