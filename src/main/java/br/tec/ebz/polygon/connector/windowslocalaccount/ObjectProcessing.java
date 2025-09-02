package br.tec.ebz.polygon.connector.windowslocalaccount;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import java.util.*;

public abstract class ObjectProcessing {
    private static final Log LOG = Log.getLog(ObjectProcessing.class);

    protected <T> T getJsonAttributeValue(JSONObject object, Class<T> type, String attributeName) {
        Object attributeValue = object.has(attributeName) ? object.get(attributeName) : null;

        if (attributeValue == null) {
            return null;
        }

        if (String.class.equals(type)) {
            String value = (String) attributeValue;

            if (value.isEmpty() || value.isBlank()) {
                return null;
            }
        }

        return (T) attributeValue;
    }

    protected List<String> convertJSONArrayToList(JSONArray jsonArray) {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < jsonArray.length(); i++) {
            list.add(jsonArray.getString(i));
        }
        return list;
    }

    protected static <T> T getAttributeValue(String name, Class<T> type, Set<Attribute> attributes) {
        LOG.ok("Processing attribute {0} of the type {1}", name, type.toString());

        Attribute attr = AttributeUtil.find(name, attributes);

        if (attr == null) {
            return null;
        }

        if (String.class.equals(type)) {
            return (T) AttributeUtil.getStringValue(attr);
        } else if (Long.class.equals(type)) {
            return (T) AttributeUtil.getLongValue(attr);
        } else if (Integer.class.equals(type)) {
            return (T) AttributeUtil.getIntegerValue(attr);
        } else if (GuardedString.class.equals(type)) {
            return (T) AttributeUtil.getGuardedStringValue(attr);
        } else if (Boolean.class.equals(type)) {
            return (T) AttributeUtil.getBooleanValue(attr);
        } else if (List.class.equals(type)) {
            return (T) attr.getValue();
        } else if(Date.class.equals(type)) {
            return (T) AttributeUtil.getDateValue(attr);
        } else {
            throw new InvalidAttributeValueException("Unknown value type " + type);
        }
    }

    protected AttributeInfo buildAttributeInfo(String name, Class type, String nativeName, AttributeInfo.Flags... flags) {

        AttributeInfoBuilder aib = new AttributeInfoBuilder(name);
        aib.setType(type);

        if (nativeName == null) {
            nativeName = name;
        }

        aib.setNativeName(nativeName);

        if (flags.length != 0) {
            Set<AttributeInfo.Flags> set = new HashSet<>();
            set.addAll(Arrays.asList(flags));
            aib.setFlags(set);
        }

        return aib.build();
    }

    protected void addAttribute(ConnectorObjectBuilder builder, String attrName, Object value) {
        //LOG.info("Processing attribute {0} with value(s) {1}", attrName, value);

        if (value == null) {
            return;
        }

        AttributeBuilder attributeBuilder = new AttributeBuilder();
        attributeBuilder.setName(attrName);

        if (value instanceof Collection) {
            attributeBuilder.addValue((Collection<?>) value);
        } else {
            attributeBuilder.addValue(value);
        }

        builder.addAttribute(attributeBuilder.build());
    }
}
