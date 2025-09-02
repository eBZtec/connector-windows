package br.tec.ebz.polygon.connector.windowslocalaccount;

import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import java.util.List;

public class SearchGroupTestOpTest extends BaseTestConnection {

    @Test(groups = "SearchGroupsTest", priority = 1)
    public void shouldReturnAllGroupsSuccessfully() {
        ConnectorFacade facade = setupConnector();

        ListResultHandler handler = new ListResultHandler();
        facade.search(ObjectClass.GROUP, null, handler, null);

        List<ConnectorObject> objects = handler.getObjects();
        AssertJUnit.assertFalse(objects.isEmpty());
    }

    @Test(groups = "SearchGroupsTest", priority = 2)
    public void shouldReturnGroupFilteredByName() {
        String name = "Administradores";
        ConnectorFacade facade = setupConnector();

        Attribute attribute = AttributeBuilder.build(Name.NAME, name);
        EqualsFilter equalsFilter = new EqualsFilter(attribute);

        ListResultHandler handler = new ListResultHandler();
        facade.search(ObjectClass.GROUP, equalsFilter, handler, null);

        List<ConnectorObject> objects = handler.getObjects();
        AssertJUnit.assertFalse(objects.isEmpty());

        AssertJUnit.assertEquals(1, objects.size());

        ConnectorObject group = objects.get(0);

        AssertJUnit.assertEquals(name, AttributeUtil.getStringValue(group.getAttributeByName("Name")));
    }

    @Test(groups = "SearchGroupsTest", priority = 3)
    public void shouldReturnAllGroupsThatUserHas() {
        String name = "";

        ConnectorFacade facade = setupConnector();

        Attribute attribute = AttributeBuilder.build(Name.NAME, name);
        ContainsFilter containsFilter = new ContainsFilter(attribute);

        ListResultHandler handler = new ListResultHandler();
        facade.search(ObjectClass.GROUP, containsFilter, handler, null);

        List<ConnectorObject> objects = handler.getObjects();
        AssertJUnit.assertFalse(objects.isEmpty());
    }
}
