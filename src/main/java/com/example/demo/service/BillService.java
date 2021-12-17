package com.example.demo.service;

import com.example.demo.model.Bill;

import java.util.List;

public interface BillService {
    void save(Bill bill);
    Bill findById(Long id);
    List<Bill> findAllBillById_User(Long id);
}
