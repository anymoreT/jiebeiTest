package api;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Random;
/**
 * Created by Administrator on 2017/3/15.
 */
public class Uitl {
    public static String getReqTime(){

        Date now_date = new Date();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        String reqTime = simpleDateFormat.format(now_date);
        return reqTime;

    }


    public static String getReqMsgId(){

        String date_str = Uitl.getReqTime();
        String reqMsgId = date_str + "1";
        int random_int = new Random().nextInt(10000000);
        String random_str = String.valueOf(random_int);
        return reqMsgId + random_str;
    }

}
