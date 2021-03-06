package com.example.demo.controllers;

import com.example.demo.dto.GoodsCartDTO;
import com.example.demo.dto.UserAnonymous;
import com.example.demo.model.Bill;
import com.example.demo.model.Goods;
import com.example.demo.model.User;
import com.example.demo.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpSession;
import java.text.SimpleDateFormat;
import java.util.*;

@Controller
@RestController
@CrossOrigin("*")
@RequestMapping("/session")
public class SessionController {
    @Autowired
    GoodsCartService goodsCartService;

    @Autowired
    CartService cartService;

    @Autowired
    UserService userService;

    @Autowired
    BillService billService;

    @Autowired
    GoodsService goodsService;

    @Autowired
    private JavaMailSender emailSender;

    public static Map<Long, GoodsCartDTO> cartItems = new HashMap<>();
    @GetMapping
    public ResponseEntity<List<GoodsCartDTO>> getCartPage(HttpSession session){
        List<GoodsCartDTO> list = new ArrayList<>();
        for (Long key: cartItems.keySet()){
            list.add(cartItems.get(key));
        }
        if(list.isEmpty()){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(list,HttpStatus.OK);
    }

    @PostMapping("/add")
    public ResponseEntity<Void> addCart(@RequestBody GoodsCartDTO goodsCartDTO) {
        if (goodsCartDTO != null) {
            if (cartItems.containsKey(goodsCartDTO.getIdGoods())) {
                GoodsCartDTO item = cartItems.get(goodsCartDTO.getIdGoods());
                item.setQuantityCart(goodsCartDTO.getQuantityCart());
                cartItems.put(goodsCartDTO.getIdGoods(), item);
            } else {
                cartItems.put(goodsCartDTO.getIdGoods(), goodsCartDTO);
            }
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/pay-money")
    public ResponseEntity<Boolean> payMoney(@RequestBody UserAnonymous userAnonymous) {
        boolean check = false;
        User user = new User();
        user.setFullName(userAnonymous.getFullName());
        user.setAddress(userAnonymous.getAddress());
        user.setEmail(userAnonymous.getEmail());
        user.setPhoneNumber(userAnonymous.getPhoneNumber());
        userService.save(user);
        Goods goods = null;
        List<GoodsCartDTO> goodsCartList = new ArrayList<>();
        for (Long key: cartItems.keySet()){
            goodsCartList.add(cartItems.get(key));
        }

        List<GoodsCartDTO> goodsCartList1 = new ArrayList<>();
        Bill bill = new Bill();
        Date date1 = new Date();
        SimpleDateFormat formatter1 = new SimpleDateFormat("dd-MM-yyyy");
        bill.setCreatedDate(formatter1.format(date1));
        bill.setBillType(true);
        bill.setUser(user);
        bill.setStatus(false);
        billService.save(bill);
        for (GoodsCartDTO goodsCart : goodsCartList) {
            check = false;
            goods = goodsService.findById(goodsCart.getIdGoods());
            if (Integer.parseInt(goods.getQuantity()) >= Integer.parseInt(goodsCart.getQuantityCart())) {
                check = true;
                goodsCartList1.add(goodsCart);
                goods.setQuantity(String.valueOf(Integer.parseInt(goods.getQuantity()) - Integer.parseInt(goodsCart.getQuantityCart())));
                goodsService.save(goods);
            }
        }
        if(check) {
            try {
                int index = 0;
                int priceSale = 0;
                int totalMoney = 0;
                MimeMessage message = this.emailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, true, "utf-8");
                helper.setTo(user.getEmail());
                helper.setSubject("H??a ????n thanh to??n");
                Date date = new Date();
                SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy");
                String dateNow = formatter.format(date);
                Calendar c = Calendar.getInstance();
                c.setTime(date);
                c.add(Calendar.DATE, 3);
                date = c.getTime();
                String dateEnd = formatter.format(date);

                System.out.println(String.format("%,.3f",(double) priceSale));

                StringBuilder mailContent = new StringBuilder(
                        "<!DOCTYPE html>\n" +
                                "<html lang=\"en\">\n" +
                                "<head>\n" +
                                "    <meta charset=\"UTF-8\">\n" +
                                "    <title>Title</title>\n" +
                                "</head>\n" +
                                "<body>\n" +
                                "<div style=\"width: 600px; margin-left: 100px; border: 1px solid black; background: rgba(255,103,184,0.16); border-radius: 6px\">\n" +
                                "    <table>\n" +
                                "        <tr>\n" +
                                "            <td>   <img src=\"{Bo link anh web vao}\" style=\"width: 60px; height: 60px;border-radius: 100%; margin-left: 5px\">\n" +
                                "            </td>\n" +
                                "            <td>\n" +
                                "                <h1 style=\"margin-left: 100px; color: #7fad39\">H??a ????n mua h??ng</h1>\n" +
                                "            </td>\n" +
                                "        </tr>\n" +
                                "\n" +
                                "    </table>\n" +
                                "    <strong style=\"margin-left: 10px \">Web Ban Hang:</strong><strong style=\"; color: #7fad39\"> OGANI</strong>   <strong style=\"margin-left: 168px\">Giao h??ng ng??y: "+ dateNow +"</strong><br>\n" +
                                "    <strong style=\"margin-left: 10px\">Email: longrin0408@gmail.com </strong>                               <strong style=\"margin-left: 83px\">Ng?????i giao: Long Bang Duy</strong><br>\n" +
                                "    <strong style=\"margin-left: 10px\"> S??t: 090.899.899</strong>                                                <strong style=\"margin-left: 223px\">D??? ki???n giao ng??y: "+ dateEnd +"</strong><br>\n" +
                                "    <br>\n" +
                                "    <strong style=\"margin-left: 200px; font-size: 20px\">C??c s???n ph???m c???a b???n</strong>\n" +
                                "    <table style=\"border-radius: 5px; border: 1px solid black; margin-left: 10px\">\n" +
                                "        <thead >\n" +
                                "        <tr style=\";border: 1px solid black\">\n" +
                                "            <td style=\"width: 110px;text-align: center;border: 1px solid black\">#</td>\n" +
                                "            <td style=\"width: 110px;text-align: center;border: 1px solid black\">C??c s???n ph???m</td>\n" +
                                "            <td style=\"width: 110px;text-align: center;border: 1px solid black\">Gi??</td>\n" +
                                "            <td style=\"width: 110px;text-align: center;border: 1px solid black\">S??? l?????ng</td>\n" +
                                "            <td style=\"width: 110px;text-align: center;border: 1px solid black\">T???ng</td>\n" +
                                "        </tr>\n" +
                                "        </thead>\n" +
                                "        <tbody>");

                for (GoodsCartDTO goodsCart : goodsCartList1) {
                    index++;
                    priceSale = Integer.parseInt(goodsCart.getPrice())*Integer.parseInt(goodsCart.getQuantityCart())-( (Integer.parseInt(goodsCart.getPrice())*Integer.parseInt(goodsCart.getQuantityCart()) * Integer.parseInt(goodsCart.getSaleOff()))/100);
                    totalMoney += priceSale;
                    mailContent.append("<tr>\n");
                    mailContent.append("<td style=\"width: 110px;text-align: center;border: 1px solid black\">");
                    mailContent.append(index);
                    mailContent.append("</td>\n");
                    mailContent.append("<td style=\"width: 110px;text-align: center;border: 1px solid black\">");
                    mailContent.append(goodsCart.getGoodsName());
                    mailContent.append("</td>\n");
                    mailContent.append("<td style=\"width: 110px;text-align: center;border: 1px solid black\">");
                    mailContent.append(String.format("%,.3f",Double.parseDouble((goodsCart.getPrice()))/1000));
                    mailContent.append(" VN??");
                    mailContent.append("</td>\n");
                    mailContent.append("<td style=\"width: 110px;text-align: center;border: 1px solid black\">");
                    mailContent.append(goodsCart.getQuantityCart());
                    mailContent.append("</td>\n");
                    mailContent.append("<td style=\"width: 110px;text-align: center;border: 1px solid black\">");
                    mailContent.append(String.format("%,.3f",(double) priceSale/1000));
                    mailContent.append(" VN??");
                    mailContent.append("</td>\n");
                    mailContent.append("</tr>\n");
                }

                mailContent.append("</tbody>\n" +
                        "    </table>\n" +
                        "    <br>\n" +
                        "    <table>\n" +
                        "        <tr>\n" +
                        "            <td>\n" +
                        "                <strong style=\"margin-left: 10px\">Ph?? giao h??ng: 15.000 VN??</strong>\n" +
                        "                <br>\n" +
                        "                <strong style=\"margin-left: 10px\">T???ng chi ph?? h??a ????n: "+ String.format("%,.3f",(double)(totalMoney + 15000)/1000)+" VN??</strong>\n" +
                        "            </td>\n" +
                        "            <td>\n" +
                        "                <img src=\"https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTMfH36G-5u3qfC1VW4_w6zqvjK1Ajcc07zHg&usqp=CAU\" style=\"width: 60px; height: 60px; margin-left: 100px\">\n" +
                        "            </td>\n" +
                        "            <td >\n" +
                        "               <strong style=\"margin-left: 10px\">Ng?????i b??n k?? t??n</strong>\n" +
                        "                <br>\n" +
                        "                <i style=\"margin-left: 37px\"> long </i><br>\n" +
                        "                <small style=\"margin-left: 10px\">Le Long</small>\n" +
                        "            </td>\n" +
                        "        </tr>\n" +
                        "\n" +
                        "    </table>\n" +
                        "    <small style=\"margin-left: 10px\"><strong>?????a ch??? giao h??ng:</strong>"+ user.getAddress()+".</small>\n" +
                        "    <hr>\n" +
                        "    <a style=\"margin-left: 10px\" href=\"(nh??t url trang home vo ????y)\">Mua h??ng t???i ????y!</a>\n" +
                        "    <p style=\"margin-left: 10px\">C???m ??n b???n ???? mua h??ng t???i website ch??ng t??i! Ch??c qu?? kh??ch vui v???.</p>\n" +
                        "</div>\n" +
                        "</body>\n" +
                        "</html>"
                );
                helper.setText(String.valueOf(mailContent), true);
                this.emailSender.send(message);
            } catch (MessagingException messaging) {
                messaging.getStackTrace();
            }
        }
        cartItems.clear();
        return new ResponseEntity<>(true, HttpStatus.OK);
    }

    @GetMapping("/reset-cart")
    public ResponseEntity<Void> resetCart(){
        cartItems.clear();
        return new ResponseEntity<>(HttpStatus.OK);
    }
}

