package br.tec.ebz.polygon.connector.windowslocalaccount;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.test.common.TestHelpers;

public class BaseTestConnection {

    public ConnectorFacade setupConnector() {
        WindowsLocalAccountConfiguration configuration = new WindowsLocalAccountConfiguration();
        configuration.setHost("");
        configuration.setHostsCA("");

        configuration.setWindowsHost("");
        configuration.setKeystoreFile("keystore/keystore.p12");
        configuration.setKeystorePassword(new GuardedString("".toCharArray()));

        configuration.setResourceID("");
        configuration.setResourceSecret(new GuardedString("".toCharArray()));

        configuration.setServerReceiveTimeout(20000);
        return setupConnector(configuration);
    }

    protected ConnectorFacade setupConnector(WindowsLocalAccountConfiguration config) {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        APIConfiguration impl = TestHelpers.createTestConfiguration(WindowsLocalAccountConnector.class, config);

        impl.getResultsHandlerConfiguration().setEnableAttributesToGetSearchResultsHandler(false);
        impl.getResultsHandlerConfiguration().setEnableCaseInsensitiveFilter(false);
        impl.getResultsHandlerConfiguration().setEnableFilteredResultsHandler(false);
        impl.getResultsHandlerConfiguration().setEnableNormalizingResultsHandler(false);
        impl.getResultsHandlerConfiguration().setFilteredResultsHandlerInValidationMode(false);

        return factory.newInstance(impl);
    }
}
