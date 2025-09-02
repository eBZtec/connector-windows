package br.tec.ebz.polygon.connector.windowslocalaccount;

import org.identityconnectors.framework.api.ConnectorFacade;
import org.testng.annotations.Test;

public class TestOpTest extends BaseTestConnection{

    @Test(groups = "test", priority = 1)
    public void shouldConnectSuccessfullyToTheServer() {
        ConnectorFacade connection = setupConnector();
        connection.test();
    }
}
