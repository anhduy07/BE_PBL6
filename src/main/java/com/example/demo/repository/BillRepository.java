package com.example.demo.repository;

import com.example.demo.model.Bill;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface BillRepository extends JpaRepository<Bill, Long> {
    String BY_ID_CART = "select*\n" +
            "from bill\n" +
            "where id_user = ?1";

    @Query(value = BY_ID_CART, nativeQuery = true)
    List<Bill> findAllBillById_User(Long id);
}
