import services.AccountInformationService;
import services.OAuthService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SandboxDispatcher {

    public void run() throws Exception {
        OAuthService oAuthService = new OAuthService();
        String appAccessToken = oAuthService.requestApplicationAccessToken();
        String customerAccessToken = oAuthService.requestCustomerAccessToken(appAccessToken);

        AccountInformationService accountInformationService = new AccountInformationService();
        String accounts = accountInformationService.requestAccountDetails(customerAccessToken);

        log.info("Account list successfully retrieved: \n {}", accounts);
    }

}
