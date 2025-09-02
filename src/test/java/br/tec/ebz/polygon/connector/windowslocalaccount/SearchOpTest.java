package br.tec.ebz.polygon.connector.windowslocalaccount;

import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import java.util.List;

public class SearchOpTest extends BaseTestConnection{

    @Test(groups = "SearchUsersTest", priority = 1)
    public void shouldListAllUsersFromWindowsLocalAccounts() throws Exception {
        ConnectorFacade facade = setupConnector();

        ListResultHandler handler = new ListResultHandler();
        facade.search(ObjectClass.ACCOUNT, null, handler, null);

        List<ConnectorObject> objects = handler.getObjects();
        AssertJUnit.assertFalse(objects.isEmpty());
    }

    @Test(groups = "SearchUsersTest", priority = 2)
    public void shouldReturnUserFilteredByLogin() {
        String name = "";

        ConnectorFacade facade = setupConnector();

        Attribute attribute = AttributeBuilder.build(Name.NAME, name);
        EqualsFilter equalsFilter = new EqualsFilter(attribute);

        ListResultHandler handler = new ListResultHandler();
        facade.search(ObjectClass.ACCOUNT, equalsFilter, handler, null);

        List<ConnectorObject> objects = handler.getObjects();
        AssertJUnit.assertFalse(objects.isEmpty());

        AssertJUnit.assertEquals(1, objects.size());
    }
}
