package br.tec.ebz.polygon.connector.windowslocalaccount;

import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.filter.*;

import java.util.List;
import java.util.Objects;

public class FilterHandler implements FilterVisitor<String, String> {
    private static final String REQUEST_TYPE_ACCOUNT_BY_NAME = "accountByName";
    private static final String REQUEST_TYPE_ALL_ACCOUNTS = "allAccounts";
    private static final String REQUEST_TYPE_ALL_GROUPS = "allGroups";
    private static final String REQUEST_TYPE_GROUPS_BY_NAME = "groupsByName";
    private static final String REQUEST_TYPE_GROUPS_FROM_ACCOUNT = "groupsFromAccount";

    private final ObjectClass objectClass;

    public FilterHandler(ObjectClass objectClass) {
        this.objectClass = objectClass;
    }

    @Override
    public String visitAndFilter(String s, AndFilter andFilter) {
        return "";
    }

    @Override
    public String visitContainsFilter(String s, ContainsFilter containsFilter) {
        Attribute attr = containsFilter.getAttribute();

        if (attr != null) {
            List<Object> values = attr.getValue();

            if (ObjectClass.GROUP.equals(objectClass)) {

                if (values == null || values.isEmpty()) {
                    return null;
                }

                String value = (String) values.get(0);
                return generateFilter(REQUEST_TYPE_GROUPS_FROM_ACCOUNT, value);
            }
        }

        return null;
    }

    @Override
    public String visitContainsAllValuesFilter(String s, ContainsAllValuesFilter containsAllValuesFilter) {
        return "";
    }

    @Override
    public String visitEqualsFilter(String s, EqualsFilter equalsFilter) {
        Attribute attr = equalsFilter.getAttribute();

        if (attr != null) {
            List<Object> values = attr.getValue();

            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                String requestType = REQUEST_TYPE_ACCOUNT_BY_NAME;

                if (values == null || values.isEmpty()) {
                    requestType = REQUEST_TYPE_ALL_ACCOUNTS;
                    return generateFilter(requestType, "");
                }

                String value = (String) values.get(0);
                return generateFilter(requestType, value);
            } else if (ObjectClass.GROUP.equals(objectClass)) {
                String requestType = REQUEST_TYPE_GROUPS_BY_NAME;

                if (values == null || values.isEmpty()) {
                    requestType = REQUEST_TYPE_ALL_GROUPS;
                    return generateFilter(requestType, "");
                }

                String value = (String) values.get(0);
                return generateFilter(requestType, value);
            }
        }

        return null;
    }

    private String generateFilter(String requestType, String filter) {
        return "{\"requestType\": \""+ requestType + "\", \"filter\": \"" + filter + "\"}";
    }

    @Override
    public String visitExtendedFilter(String s, Filter filter) {
        return "";
    }

    @Override
    public String visitGreaterThanFilter(String s, GreaterThanFilter greaterThanFilter) {
        return "";
    }

    @Override
    public String visitGreaterThanOrEqualFilter(String s, GreaterThanOrEqualFilter greaterThanOrEqualFilter) {
        return "";
    }

    @Override
    public String visitLessThanFilter(String s, LessThanFilter lessThanFilter) {
        return "";
    }

    @Override
    public String visitLessThanOrEqualFilter(String s, LessThanOrEqualFilter lessThanOrEqualFilter) {
        return "";
    }

    @Override
    public String visitNotFilter(String s, NotFilter notFilter) {
        return "";
    }

    @Override
    public String visitOrFilter(String s, OrFilter orFilter) {
        return "";
    }

    @Override
    public String visitStartsWithFilter(String s, StartsWithFilter startsWithFilter) {
        return "";
    }

    @Override
    public String visitEndsWithFilter(String s, EndsWithFilter endsWithFilter) {
        return "";
    }

    @Override
    public String visitEqualsIgnoreCaseFilter(String s, EqualsIgnoreCaseFilter equalsIgnoreCaseFilter) {
        return "";
    }
}
