package com.example.demo.dto;


public class GoodsDTO {
    private Long idGoods;
    private String goodsName;
    private String price;
    private String quantity;
    private String tradeMark;
    private String saleOff;
    private String priceForSaleOff;
    private String image;
    private String category;
    private String favourite;
    private String description;

    public GoodsDTO(Long idGoods, String goodsName, String price, String quantity, String tradeMark, String saleOff, String priceForSaleOff, String image, String category, String favourite, String description) {
        this.idGoods = idGoods;
        this.goodsName = goodsName;
        this.price = price;
        this.quantity = quantity;
        this.tradeMark = tradeMark;
        this.saleOff = saleOff;
        this.priceForSaleOff = priceForSaleOff;
        this.image = image;
        this.category = category;
        this.favourite = favourite;
        this.description = description;
    }

    public String getFavourite() {
        return favourite;
    }

    public void setFavourite(String favourite) {
        this.favourite = favourite;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Long getIdGoods() {
        return idGoods;
    }

    public void setIdGoods(Long idGoods) {
        this.idGoods = idGoods;
    }

    public String getGoodsName() {
        return goodsName;
    }

    public void setGoodsName(String goodsName) {
        this.goodsName = goodsName;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    public String getQuantity() {
        return quantity;
    }

    public void setQuantity(String quantity) {
        this.quantity = quantity;
    }

    public String getTradeMark() {
        return tradeMark;
    }

    public void setTradeMark(String tradeMark) {
        this.tradeMark = tradeMark;
    }

    public String getSaleOff() {
        return saleOff;
    }

    public void setSaleOff(String saleOff) {
        this.saleOff = saleOff;
    }

    public String getPriceForSaleOff() {
        return priceForSaleOff;
    }

    public void setPriceForSaleOff(String priceForSaleOff) {
        this.priceForSaleOff = priceForSaleOff;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }
}
