package com.example.demo.repository;

import com.example.demo.model.Goods;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface GoodsRepository extends JpaRepository<Goods, Long> {
    List<Goods> findAllByCategory_IdCategory(Long id);

    List<Goods> findAllByGoodsNameContaining(String name);
}
