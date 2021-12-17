package com.example.demo.controllers;

import com.example.demo.dto.GoodsDTO;
import com.example.demo.model.*;
import com.example.demo.repository.BillRepository;
import com.example.demo.repository.CategoryRepository;
import com.example.demo.service.BillService;
import com.example.demo.service.CategoryService;
import com.example.demo.service.GoodsService;
import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
@RestController
@CrossOrigin
@RequestMapping("/goods")
public class GoodsController {
    @Autowired
    GoodsService goodsService;
    @Autowired
    UserService userService;
    @Autowired
    CategoryService categoryService;
    @Autowired
    BillService billService;
    @Autowired
    BillRepository billRepository;

    @Autowired
    CategoryRepository categoryRepository;

    @Autowired
    private JavaMailSender emailSender;
    public static Boolean check = false;

    @GetMapping("/getAll")
    public ResponseEntity<List<Goods>> getAllGoods(){
        List<Goods> goodsList = goodsService.findAllGoods();
        if(goodsList.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(goodsList, HttpStatus.OK);
    }
    @GetMapping("/findById/{id}")
    public ResponseEntity<Goods> findById(@PathVariable("id") Long id){
        Goods goods = goodsService.findById(id);
        if(goods == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(goods, HttpStatus.OK);
    }

    @GetMapping("/searchByGoodsType")
    public ResponseEntity<List<Goods>> searchByGoodsType(@RequestParam("valueSearch") String valueSearch){
        List<Goods> goodsList = goodsService.findAllByCategory_IdCategory(Long.parseLong(valueSearch));
        return new ResponseEntity<>(goodsList, HttpStatus.OK);
    }
    @GetMapping("/getAllTypeGoods")
    public ResponseEntity<List<Category>> getAllTypeGoods(){
        List<Category> categories = categoryRepository.findAll();
        if(categories.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(categories, HttpStatus.OK);
    }
    @GetMapping("/find-by")
    public ResponseEntity<User> findByUser(@RequestParam("username") String username){
        User user = userService.findByUsername(username);
        if(user == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
    @GetMapping("/inputSearch/{value}")
    public ResponseEntity<List<Goods>> inputSearch(@PathVariable("value") String value) {
        List<Goods> goodsList = goodsService.findAllByGoodsNameContaining(value);
        if(goodsList.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(goodsList, HttpStatus.OK);
    }
    @GetMapping("/getBillDetail/{idBill}")
    public ResponseEntity<List<GoodsCart>> getBillDetail(@PathVariable("idBill") Long idBill) {
        Bill bill = billService.findById(idBill);
        if (bill == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        List<GoodsCart> goodsCartList = (List<GoodsCart>) bill.getGoodsCartCollection();
        if(goodsCartList.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(goodsCartList, HttpStatus.OK);
    }
    @GetMapping("/getAllBill")
    public ResponseEntity<List<Bill>> getAllBill() {
        List<Bill> billList = billRepository.findAll();
        if(billList.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(billList, HttpStatus.OK);
    }
    @GetMapping("/setFavourite/{id}")
    public ResponseEntity<Void> setFavourite(@PathVariable("id") Long id) {
        Goods goods = goodsService.findById(id);
        if(goods == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        goods.setFavourite(String.valueOf(Long.parseLong(goods.getFavourite())+ 1)  );
        goodsService.save(goods);
        return new ResponseEntity<>(HttpStatus.OK);
    }
    @GetMapping("/getCheck")
    public ResponseEntity<Boolean> getCheck() {
        return new ResponseEntity<>(check, HttpStatus.OK);
    }
    @GetMapping("/setCheck/{value}")
    public ResponseEntity<Void> setCheck(@PathVariable("value") String value) {
      check = Boolean.parseBoolean(value);
        return new ResponseEntity<>(HttpStatus.OK);
    }
    @DeleteMapping("/deleteById/{value}")
    public ResponseEntity<Void> deleteById(@PathVariable("value") Long value) {
        Goods goods = goodsService.findById(value);
        if(goods == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        goodsService.deleteById(value);
        return new ResponseEntity<>(HttpStatus.OK);
    }
    @GetMapping("/getAllGoods-dto")
    public ResponseEntity<List<GoodsDTO>> getAllGoodsDTO(){
        List<Goods> goodsList = goodsService.findAllGoods();
        if(goodsList.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        List<GoodsDTO> dtoList = new ArrayList<>();
        for(Goods goods: goodsList){
            dtoList.add(new GoodsDTO(goods.getIdGoods(),goods.getGoodsName(),goods.getPrice(),goods.getQuantity(),goods.getTradeMark(),goods.getSaleOff(),goods.getPriceForSaleOff(),goods.getImage(),goods.getCategory().getIdCategory()+ "",goods.getFavourite(),goods.getDescription()));
        }
        return new ResponseEntity<>(dtoList, HttpStatus.OK);
    }

    @PatchMapping("/edit/{id}")
    public ResponseEntity<Void> editGoods(@PathVariable("id") Long id, @RequestBody GoodsDTO goodsDTO) {
        Goods goodsNew = goodsService.findById(id);
        if (goodsNew == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } else {
            goodsNew.setImage(goodsDTO.getImage());
            goodsNew.setQuantity(goodsDTO.getQuantity());
            goodsNew.setGoodsName(goodsDTO.getGoodsName());
            goodsNew.setCategory(categoryService.findById(Long.parseLong(goodsDTO.getCategory())));
            goodsNew.setImage(goodsDTO.getImage());
            goodsNew.setPrice(goodsDTO.getPrice());
            goodsNew.setSaleOff(goodsDTO.getSaleOff());
            goodsNew.setSaleOff(goodsDTO.getDescription());
            goodsNew.setSaleOff("0");
            goodsService.save(goodsNew);
            return new ResponseEntity<>(HttpStatus.OK);
        }
    }
    @PostMapping("/create")
    public ResponseEntity<Void> createGoods(@RequestBody GoodsDTO goodsDTO) {
        Goods goodsNew = new Goods();
        goodsNew.setImage(goodsDTO.getImage());
        goodsNew.setQuantity(goodsDTO.getQuantity());
        goodsNew.setGoodsName(goodsDTO.getGoodsName());
        goodsNew.setCategory(categoryService.findById(Long.parseLong(goodsDTO.getCategory())));
        goodsNew.setImage(goodsDTO.getImage());
        goodsNew.setPrice(goodsDTO.getPrice());
        goodsNew.setSaleOff(goodsDTO.getSaleOff());
        goodsNew.setSaleOff(goodsDTO.getDescription());
        goodsNew.setSaleOff("0");
        goodsService.save(goodsNew);
        return new ResponseEntity<>(HttpStatus.OK);
        }
}
