/**
 * Created by Administrator on 2017/3/15.
 */
import api.RSADemo;
import api.Uitl;
import org.testng.annotations.Test;

public class TestApi {
    @Test
    public  void testMD5(){
//        RSADemo.check();
//        String reqTime;
//        String reqMsgId;
//        reqTime = Uitl.getReqTime();
//        reqMsgId = Uitl.getReqMsgId();
//        System.out.println("\n" + reqTime);
//        System.out.println("\n" + reqMsgId);

        String request = RSADemo.get_institution_credit_apply("340822199105180249","熊小咖", "13223456543");
        System.out.println("\n" + request);


    }
}