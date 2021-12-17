package com.example.demo.dto;

public class GoodsCartDTO {
    private Long idGoodsCart;
    private Long idGoods;
    private String quantityCart;
    private String goodsName;
    private String price;
    private String tradeMark;
    private String saleOff;
    private String priceForSaleOff;
    private String image;
    private Long cart;
    private Boolean status;
    private String totalQuantity;

    public GoodsCartDTO() {
    }

    public GoodsCartDTO(Long idGoodsCart, Long idGoods, String quantityCart, String goodsName, String price, String tradeMark, String saleOff, String priceForSaleOff, String image, Long cart, Boolean status, String totalQuantity ) {
        this.idGoodsCart = idGoodsCart;
        this.idGoods = idGoods;
        this.quantityCart = quantityCart;
        this.goodsName = goodsName;
        this.price = price;
        this.tradeMark = tradeMark;
        this.saleOff = saleOff;
        this.priceForSaleOff = priceForSaleOff;
        this.image = image;
        this.cart = cart;
        this.status = status;
        this.totalQuantity = totalQuantity;
    }

    public String getTotalQuantity() {
        return totalQuantity;
    }

    public void setTotalQuantity(String totalQuantity) {
        this.totalQuantity = totalQuantity;
    }

    public Boolean getStatus() {
        return status;
    }

    public void setStatus(Boolean status) {
        this.status = status;
    }

    public Long getIdGoodsCart() {
        return idGoodsCart;
    }

    public void setIdGoodsCart(Long idGoodsCart) {
        this.idGoodsCart = idGoodsCart;
    }

    public Long getIdGoods() {
        return idGoods;
    }

    public void setIdGoods(Long idGoods) {
        this.idGoods = idGoods;
    }

    public String getQuantityCart() {
        return quantityCart;
    }

    public void setQuantityCart(String quantityCart) {
        this.quantityCart = quantityCart;
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

    public Long getCart() {
        return cart;
    }

    public void setCart(Long cart) {
        this.cart = cart;
    }
}
