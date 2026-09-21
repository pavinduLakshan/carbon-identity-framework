/*
 * Copyright (c) 2014-2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.user.store.configuration.utils;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants.UserStoreState;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.store.configuration.beans.MaskedProperty;
import org.wso2.carbon.identity.user.store.configuration.dao.UserStoreDAO;
import org.wso2.carbon.identity.user.store.configuration.dao.impl.FileBasedUserStoreDAOFactory;
import org.wso2.carbon.identity.user.store.configuration.dto.PropertyDTO;
import org.wso2.carbon.identity.user.store.configuration.dto.UserStoreDTO;
import org.wso2.carbon.identity.user.store.configuration.internal.UserStoreConfigComponent;
import org.wso2.carbon.identity.user.store.configuration.internal.UserStoreConfigListenersHolder;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreClientException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;
import org.wso2.carbon.user.core.tracker.UserStoreManagerRegistry;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.ALLOWED_CONNECTION_URL_PROPERTY_CONFIG;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.CONNECTION_URL_PROPERTY_KEY_VALUE_SEPARATOR;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.CONNECTION_URL_PROPERTY_SEPARATOR;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.CONNECTION_URL_PROPERTY_VALUE_REGEX;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.DENIED_CONNECTION_URL_PROPERTIES;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.DEPLOYMENT_DIRECTORY;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.ENCRYPTED_PROPERTY_MASK;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.ESCAPED_SEMICOLON;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.FILE_EXTENSION_XML;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.USERSTORES;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant.VALIDATION_QUERY_REGEX;

/**
 * Util class responsible for processing encryption and decryption over secondary user store
 */
public class SecondaryUserStoreConfigurationUtil {

    private static final Log LOG = LogFactory.getLog(SecondaryUserStoreConfigurationUtil.class);

    private static final Set<String> DENIED_PROPERTIES = new HashSet<>(Arrays.asList(DENIED_CONNECTION_URL_PROPERTIES));

    // H2 JDBC URL prefixes. Anything other than the in memory and server forms is file backed.
    private static final String H2_URL_PREFIX = "jdbc:h2:";
    private static final String H2_MEMORY_URL_PREFIX = "jdbc:h2:mem:";
    private static final String H2_TCP_URL_PREFIX = "jdbc:h2:tcp://";
    private static final String H2_SSL_URL_PREFIX = "jdbc:h2:ssl://";

    private static final Pattern CONNECTION_URL_PROPERTY_VALUE_PATTERN =
            Pattern.compile(CONNECTION_URL_PROPERTY_VALUE_REGEX);

    private static final Pattern VALIDATION_QUERY_PATTERN = Pattern.compile(VALIDATION_QUERY_REGEX);

    /**
     * Statement terminator. A validation query may end with one, but may not contain one anywhere else.
     */
    private static final String STATEMENT_TERMINATOR = ";";

    private SecondaryUserStoreConfigurationUtil() {

    }

    /**
     * @param plainText Cipher text to be encrypted
     * @return Returns the encrypted text
     * @throws IdentityUserStoreMgtException Encryption failed
     */
    public static String encryptPlainText(String plainText) throws IdentityUserStoreMgtException {

        SecondaryUserStoreConfigurator configurator = new SecondaryUserStoreConfigurator();
        return configurator.encryptPlainText(plainText);
    }

    /**
     * To get the path of the userStore XML file
     * @param domainName userStore domain name
     * @return the path of the userstore xml
     * @throws IdentityUserStoreMgtException if an error occurs when getting the file path.
     */
    public static Path getUserStoreConfigurationFile(String domainName) throws IdentityUserStoreMgtException {

        String fileName = domainName.replace(UserStoreConfigurationConstant.PERIOD,
                UserStoreConfigurationConstant.UNDERSCORE);
        Path userStore;

        if (!IdentityUtil.isValidFileName(fileName)) {
            String message = "Provided domain name : '" + domainName + "' is invalid.";
            throw new IdentityUserStoreMgtException(message);
        }

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
            userStore = Paths.get(DEPLOYMENT_DIRECTORY);
        } else {
            String tenantFilePath = CarbonUtils.getCarbonTenantsDirPath();
            userStore = Paths.get(tenantFilePath, String.valueOf(tenantId), USERSTORES);
        }
        return getUserStoreConfigFile(userStore, fileName);
    }

    private static Path getUserStoreConfigFile(Path userStore, String fileName) {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (!Files.exists(userStore)) {
            try {
                Files.createDirectory(userStore);
                LOG.info("folder 'userstores' created to store configurations for tenant = " + tenantId);
            } catch (IOException e) {
                LOG.error("Error while creating 'userstores' directory to store configurations for tenant = "
                          + tenantId);
            }
        }
        return Paths.get(userStore.toString(), fileName + FILE_EXTENSION_XML);
    }

    /**
     * This method is used to write userStore xml file.
     *
     * @deprecated use {@link #writeUserMgtXMLFile(Path, UserStoreDTO, boolean, boolean, String)} instead.
     */
    @Deprecated
    public static void writeUserMgtXMLFile(Path userStoreConfigFile, UserStoreDTO userStoreDTO,
                                           boolean editSecondaryUserStore, boolean isStateChange)
            throws IdentityUserStoreMgtException {

        writeUserMgtXMLFile(userStoreConfigFile, userStoreDTO, editSecondaryUserStore, isStateChange,
                userStoreDTO.getDomainId());
    }

    /**
     * This method is used to write userStore xml file.
     * @param userStoreConfigFile path of the userStore configuration file
     * @param userStoreDTO instance of {@link UserStoreDTO}
     * @param editSecondaryUserStore true if it is update operation
     * @param  existingDomainName domain name of existing userstore
     * @throws IdentityUserStoreMgtException throws if an error occurred while writing to the xml file.
     */
    public static void writeUserMgtXMLFile(Path userStoreConfigFile, UserStoreDTO userStoreDTO,
                                           boolean editSecondaryUserStore, boolean isStateChange,
                                           String existingDomainName)
            throws IdentityUserStoreMgtException {

        boolean isDisable = false;
        if (userStoreDTO.getDisabled() != null) {
            isDisable = userStoreDTO.getDisabled();
        }
        String domain = userStoreDTO.getDomainId();
        DocumentBuilderFactory documentFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
        DocumentBuilder documentBuilder;

        try {
            documentBuilder = documentFactory.newDocumentBuilder();

            if (isStateChange) {
                updateStateOfUserStore(userStoreConfigFile, isDisable, domain, documentBuilder);
            } else {
                updateUserStoreProperties(userStoreConfigFile, userStoreDTO, editSecondaryUserStore, documentBuilder,
                        existingDomainName);
            }
        } catch (ParserConfigurationException e) {
            String errMsg = " Error occurred due to serious parser configuration exception of " + userStoreConfigFile;
            throw new IdentityUserStoreMgtException(errMsg, e);
        } catch (TransformerException e) {
            String errMsg = " Error occurred during the transformation process of " + userStoreConfigFile;
            throw new IdentityUserStoreMgtException(errMsg, e);
        } catch (IOException e) {
            String errMsg = " Error occurred while creating or closing the output stream from " + userStoreConfigFile;
            throw new IdentityUserStoreMgtException(errMsg, e);
        } catch (SAXException e) {
            throw new IdentityUserStoreMgtException("Error while updating user store state", e);
        }
    }


    /**
     * This method is used to Get the user store config file.
     *
     * @deprecated use {@link #getUserStoreProperties(UserStoreDTO, String)} instead.
     */
    @Deprecated
    public static String getUserStoreProperties(UserStoreDTO userStoreDTO) throws IdentityUserStoreMgtException {
        return getUserStoreProperties(userStoreDTO, userStoreDTO.getDomainId());
    }

    /**
     * Get the user store config file.
     * @param userStoreDTO an instance of {@link UserStoreDTO}
     * @param existingDomainName existing userstore domain name
     * @return user store properties as a String.
     * @throws IdentityUserStoreMgtException throws if an error occurred while getting the user store properties.
     */
    public static String getUserStoreProperties(UserStoreDTO userStoreDTO, String existingDomainName)
            throws IdentityUserStoreMgtException {

        String userStoreProperties;
        DocumentBuilderFactory documentFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
        try {
            DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
            Document doc = getDocument(userStoreDTO, false, documentBuilder, existingDomainName);
            StringWriter writer = new StringWriter();
            transformProperties().transform(new DOMSource(doc), new StreamResult(writer));
            //To replace the line breaks
            userStoreProperties = writer.getBuffer().toString().replaceAll("\n|\r", "");

        } catch (ParserConfigurationException | TransformerException e) {
            throw new IdentityUserStoreMgtException("Error occured while parsing the user store file.", e);
        } catch (IdentityUserStoreMgtException e) {
            throw new IdentityUserStoreMgtException("Error occured while getting the user store properties.", e);
        }
        return userStoreProperties;
    }

    public static Map<String, String> getSecondaryUserStorePropertiesFromTenantUserRealm(String userStoreDomain)
            throws IdentityUserStoreMgtException {

        Map<String, String> secondaryUserStoreProperties = null;
        try {
            RealmConfiguration realmConfiguration = UserStoreConfigComponent.getRealmService().getTenantUserRealm(
                    getTenantIdInTheCurrentContext()).getRealmConfiguration();
            while (realmConfiguration != null) {
                String domainName = realmConfiguration.getUserStoreProperty(UserCoreConstants.RealmConfig
                        .PROPERTY_DOMAIN_NAME);
                if (StringUtils.equalsIgnoreCase(domainName, userStoreDomain)) {
                    secondaryUserStoreProperties = realmConfiguration.getUserStoreProperties();
                    break;
                } else {
                    realmConfiguration = realmConfiguration.getSecondaryRealmConfig();
                }
            }
        } catch (UserStoreException e) {
            String errorMessage = "Error while retrieving user store configurations for user store domain: "
                    + userStoreDomain;
            throw new IdentityUserStoreMgtException(errorMessage, e);
        }
        return secondaryUserStoreProperties;
    }

    private static Transformer transformProperties() throws TransformerException {

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "6");
        return transformer;
    }

    private static void updateUserStoreProperties(Path userStoreConfigFile, UserStoreDTO userStoreDTO,
                                                  boolean editSecondaryUserStore, DocumentBuilder documentBuilder,
                                                  String existingDomainName)
            throws IdentityUserStoreMgtException, IOException, TransformerException {

        Document doc = getDocument(userStoreDTO, editSecondaryUserStore, documentBuilder, existingDomainName);
        StreamResult result = new StreamResult(Files.newOutputStream(userStoreConfigFile));
        DOMSource source = new DOMSource(doc);
        transformProperties().transform(source, result);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Closing the output stream from " + userStoreConfigFile);
        }
        result.getOutputStream().close();

    }

    private static Document getDocument(UserStoreDTO userStoreDTO, boolean editSecondaryUserStore,
                                        DocumentBuilder documentBuilder, String existingDomainName)
            throws IdentityUserStoreMgtException {

        Document doc = documentBuilder.newDocument();

        //create UserStoreManager element
        Element userStoreElement = doc.createElement(UserCoreConstants.RealmConfig.LOCAL_NAME_USER_STORE_MANAGER);
        doc.appendChild(userStoreElement);

        Attr attrClass = doc.createAttribute("class");
        if (userStoreDTO != null) {
            attrClass.setValue(userStoreDTO.getClassName());
            userStoreElement.setAttributeNode(attrClass);
            if (userStoreDTO.getClassName() != null) {
                addProperties(existingDomainName, userStoreDTO.getClassName(), userStoreDTO.getProperties(),
                        doc, userStoreElement, editSecondaryUserStore);
            }
            addProperty(UserStoreConfigConstants.DOMAIN_NAME, userStoreDTO.getDomainId(), doc, userStoreElement, false);
            addProperty(UserStoreConfigurationConstant.DESCRIPTION, userStoreDTO.getDescription(), doc,
                        userStoreElement, false);
        }
        return doc;
    }

    private static void updateStateOfUserStore(Path userStoreConfigFile, boolean isDisable, String domain,
                                               DocumentBuilder documentBuilder) throws SAXException, IOException,
            TransformerException {

        Document doc = documentBuilder.parse(Files.newInputStream(userStoreConfigFile));

        NodeList elements = doc.getElementsByTagName("Property");
        for (int i = 0; i < elements.getLength(); i++) {
            //Assumes a property element only have attribute 'name'
            if ("Disabled".compareToIgnoreCase(elements.item(i).getAttributes().item(0).getNodeValue()) == 0) {
                elements.item(i).setTextContent(String.valueOf(isDisable));
                break;
            }
        }
        StreamResult result = new StreamResult(Files.newOutputStream(userStoreConfigFile));
        DOMSource source = new DOMSource(doc);
        transformProperties().transform(source, result);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Closing the output stream from " + userStoreConfigFile);
        }
        result.getOutputStream().close();

        if (LOG.isDebugEnabled()) {
            LOG.debug("New state :" + isDisable + " of the user store \'" + domain + "\' successfully " +
                      "written to the file system");
        }
    }

    /**
     * Obtains the mandatory properties for a given userStoreClass
     *
     * @param userStoreClass userStoreClass name
     * @return Property[] of Mandatory Properties
     */
    private static Property[] getMandatoryProperties(String userStoreClass) {

        return UserStoreManagerRegistry.getUserStoreProperties(userStoreClass).getMandatoryProperties();
    }

    /**
     * Check whether the given property should be encrypted or not.
     *
     * @param mandatoryProperties mandatory property array
     * @param propertyName        property name
     * @return returns true if the property should be encrypted
     */
    private static boolean isPropertyToBeEncrypted(Property[] mandatoryProperties,
                                                   String propertyName) {

        for (Property property : mandatoryProperties) {
            if (propertyName.equalsIgnoreCase(property.getName())) {
                return property.getDescription().contains(UserStoreConfigurationConstant.ENCRYPT_TEXT);
            }
        }
        return false;
    }

    /**
     * Adds a property
     *
     * @param name:   Name of property
     * @param value:  Value
     * @param doc:    Document
     * @param parent: Parent element of the property to be added as a child
     */
    private static void addProperty(String name, String value, Document doc, Element parent, boolean encrypted) {
        Element property = doc.createElement("Property");
        Attr attr;
        if (encrypted) {
            attr = doc.createAttribute("encrypted");
            attr.setValue("true");
            property.setAttributeNode(attr);
        }

        attr = doc.createAttribute("name");
        attr.setValue(name);
        property.setAttributeNode(attr);

        property.setTextContent(value);
        parent.appendChild(property);
    }

    /**
     * Adds an array of properties
     *
     * @param propertyDTOs List of user store properties
     * @param doc          Document
     * @param parent       Parent element of the properties to be added
     */
    private static void addProperties(String userStoreDomain, String userStoreClass, PropertyDTO[] propertyDTOs,
                                      Document doc, Element parent, boolean editSecondaryUserStore)
            throws IdentityUserStoreMgtException {

        if (editSecondaryUserStore) {
            String uniqueID = findPropertyValue(propertyDTOs, UserStoreConfigurationConstant.UNIQUE_ID_CONSTANT);
            if (uniqueID == null) {
                throw new IdentityUserStoreMgtException("UniqueID property is not provided.");
            }
        }

        //First check for mandatory field with #encrypt
        Property[] mandatoryProperties = getMandatoryProperties(userStoreClass);

        Map<String, String> secondaryUserStoreProperties =
                getSecondaryUserStorePropertiesFromTenantUserRealm(userStoreDomain);

        // Read ahead: the connectionProperties rules are scoped by the driver, which the URL identifies.
        String connectionUrl = findPropertyValue(propertyDTOs, JDBCRealmConstants.URL);

        for (PropertyDTO propertyDTO : propertyDTOs) {
            String propertyDTOName = propertyDTO.getName();
            if (UserStoreConfigurationConstant.UNIQUE_ID_CONSTANT.equalsIgnoreCase(propertyDTOName)) {
                continue;
            }

            String propertyDTOValue = propertyDTO.getValue();
            if (propertyDTOValue != null) {
                if (JDBCRealmConstants.URL.equalsIgnoreCase(propertyDTOName)) {
                    validateJdbcConnectionUrl(propertyDTOValue);
                }
                if (JDBCRealmConstants.VALIDATION_QUERY.equalsIgnoreCase(propertyDTOName)) {
                    validateValidationQuery(propertyDTOValue);
                }
                if (JDBCRealmConstants.CONNECTION_PROPERTIES.equalsIgnoreCase(propertyDTOName)) {
                    validateConnectionProperties(propertyDTOValue, connectionUrl);
                }
                boolean encrypted = false;
                if (isPropertyToBeEncrypted(mandatoryProperties, propertyDTOName)) {
                    propertyDTOValue = getPropertyValueIfMasked(secondaryUserStoreProperties, propertyDTOName,
                            propertyDTOValue);
                    try {
                        propertyDTOValue = SecondaryUserStoreConfigurationUtil.encryptPlainText(propertyDTOValue);
                        encrypted = true;
                    } catch (IdentityUserStoreMgtException e) {
                        LOG.error("addProperties failed to encrypt", e);
                        //its ok to continue from here
                    }
                }
                addProperty(propertyDTOName, propertyDTOValue, doc, parent, encrypted);
            }
        }
    }

    /**
     * If the property value is a mask value, this method will return the corresponding property value.
     *
     * @param secondaryUserStoreProperties Value {@link Map} of a the secondary user store, where actual value is
     *                                     pulled instead of the mask.
     * @param propertyDTOName   Name of the property.
     * @param propertyDTOValue Value of the property.
     * @return If property value is masked, returns the actual value to be stored instead of the mask. Otherwise the
     * same propertyDTOValue passed as the argument.
     */
    private static String getPropertyValueIfMasked(Map<String, String> secondaryUserStoreProperties,
                                                   String propertyDTOName, String propertyDTOValue) {

        if (ENCRYPTED_PROPERTY_MASK.equalsIgnoreCase(propertyDTOValue)) {
            propertyDTOValue = getExistingPropertyValue(secondaryUserStoreProperties, propertyDTOName);
        }
        return propertyDTOValue;
    }

    private static String getExistingPropertyValue(Map<String, String> secondaryUserStoreProperties,
                                                   String propertyDTOName) {

        String existingPropertyValue = null;
        if (secondaryUserStoreProperties != null) {
            existingPropertyValue = secondaryUserStoreProperties.get(propertyDTOName);
        }
        return existingPropertyValue;
    }

    private static UserStoreManager getSecondaryUserStoreManager(String userStoreDomain) throws UserStoreException {

        UserStoreManager secondaryUserStoreManager = null;
        UserRealm userRealm = (UserRealm) UserStoreConfigComponent.getRealmService().getTenantUserRealm(
                getTenantIdInTheCurrentContext());
        UserStoreManager userStoreManager = userRealm.getUserStoreManager();
        if (userStoreManager != null) {
            secondaryUserStoreManager = userStoreManager.getSecondaryUserStoreManager(userStoreDomain);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not locate user store manager for user store domain: " + userStoreDomain);
            }
        }
        return secondaryUserStoreManager;
    }

    private static int getTenantIdInTheCurrentContext() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    /**
     * This method is used to validate the domain name. Should not allow to have domain prefixed with 'FEDERATED', to
     * avoid conflicting with federated user domain.
     *
     * @param domain domain name
     * @throws UserStoreException throws if an error occured while validating the domain.
     */
    public static void validateForFederatedDomain(String domain) throws UserStoreException {

        if (IdentityUtil.isNotBlank(domain) && domain.toUpperCase().startsWith(UserStoreConfigurationConstant
                                                                                       .FEDERATED)) {
            throw new UserStoreException("'FEDERATED' is a reserved user domain prefix. "
                    + "Please start the domain name in a different manner.");
        }
    }

    /**
     * To get instance of {@link FileBasedUserStoreDAOFactory}
     *
     * @return an instance of {@link FileBasedUserStoreDAOFactory}
     * @throws UserStoreException throws when instantiating {@link FileBasedUserStoreDAOFactory}
     */
    public static UserStoreDAO getFileBasedUserStoreDAOFactory() throws UserStoreException {

        UserStoreDAO userStoreDAO = UserStoreConfigListenersHolder.getInstance().getUserStoreDAOFactories()
                .get(FileBasedUserStoreDAOFactory.class.getName()).getInstance();
        if (userStoreDAO == null) {
            throw new UserStoreException("Error occured while creating an instance of FileBasedUserStoreDAOFactory.");
        }
        return userStoreDAO;
    }

    /**
     * get random passwords generated.
     * @param secondaryRealmConfiguration realm configuration.
     * @param userStoreProperties user store properties.
     * @param encryptPropertyMaskValue The value used as the mask.
     * @param className class name
     * @return The array of {@link MaskedProperty} for the user store.
     */
    public static MaskedProperty[] setMaskInUserStoreProperties(RealmConfiguration secondaryRealmConfiguration,
                                                                Map<String, String> userStoreProperties,
                                                                String encryptPropertyMaskValue, String className) {

        MaskedProperty[] maskedProperties = getMaskedProperties(className, encryptPropertyMaskValue,
                secondaryRealmConfiguration);

        for (MaskedProperty maskedProperty : maskedProperties) {
            userStoreProperties.put(maskedProperty.getName(), maskedProperty.getMask());
        }

        return maskedProperties;
    }

    private static MaskedProperty[] getMaskedProperties(String userStoreClass, String maskValue,
                                                        RealmConfiguration secondaryRealmConfiguration) {
        //First check for mandatory field with #encrypt
        Property[] mandatoryProperties = getMandatoryProperties(userStoreClass);
        ArrayList<MaskedProperty> maskedProperties = new ArrayList<>();
        for (Property property : mandatoryProperties) {
            String propertyName = property.getName();
            if (property.getDescription().contains(UserStoreConfigurationConstant.ENCRYPT_TEXT)) {
                MaskedProperty maskedProperty = new MaskedProperty();
                maskedProperty.setName(propertyName);
                maskedProperty.setValue(secondaryRealmConfiguration.getUserStoreProperty(propertyName));
                maskedProperty.setMask(maskValue);
                maskedProperties.add(maskedProperty);
            }
        }
        return maskedProperties.toArray(new MaskedProperty[0]);
    }

    /**
     * To convert user store properties map to an array.
     * @param properties user store properties map
     * @return userstore properties array
     */
    public static PropertyDTO[] convertMapToArray(Map<String, String> properties) {

        Set<Map.Entry<String, String>> propertyEntries = properties.entrySet();
        ArrayList<PropertyDTO> propertiesList = new ArrayList<PropertyDTO>();
        String key;
        String value;
        for (Map.Entry<String, String> entry : propertyEntries) {
            key = (String) entry.getKey();
            value = (String) entry.getValue();
            PropertyDTO propertyDTO = new PropertyDTO(key, value);
            propertiesList.add(propertyDTO);
        }
        return propertiesList.toArray(new PropertyDTO[propertiesList.size()]);
    }

    /**
     * Trigger the listeners before userstore name update
     * @param previousDomainName previous user store domain name
     * @param domainName current user store domain name
     * @throws UserStoreException throws when an error occured when triggering listeners.
     */
    public static void triggerListnersOnUserStorePreUpdate(String previousDomainName, String domainName)
            throws UserStoreException {

        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();
        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore pre update listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStoreNamePreUpdate(CarbonContext.getThreadLocalCarbonContext().getTenantId
                    (), previousDomainName, domainName);
        }
    }

    /**
     * Trigger the listeners after a userstore name update.
     *
     * @param previousDomainName Previous userstore domain name.
     * @param newDomainName      Current(new) userstore domain name.
     * @throws UserStoreException If an error occurred while invoking post listeners.
     */
    public static void triggerListenersOnUserStorePostUpdate(String previousDomainName, String newDomainName)
            throws UserStoreException {

        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();
        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering post userstore domain update listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStoreNamePostUpdate(CarbonContext.getThreadLocalCarbonContext().getTenantId(),
                    previousDomainName, newDomainName);
        }
    }

    /**
     * Trigger the listeners before userstore domain delete
     *
     * @param domainName user store domain name
     * @throws UserStoreException throws when an error occured when triggering listeners.
     */
    public static void triggerListnersOnUserStorePreDelete(String domainName) throws UserStoreException {

        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();
        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore pre delete listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStorePreDelete(CarbonContext.getThreadLocalCarbonContext().getTenantId
                    (), domainName);
        }
    }

    /**
     * Trigger the listeners before a user store state is changed.
     *
     * @param domainName User store domain name.
     * @param isDisable True if disabled, else false.
     * @throws UserStoreException Thrown when an error occurred while triggering listeners.
     */
    public static void triggerListenersOnUserStorePreStateChange(String domainName, boolean isDisable)
            throws UserStoreException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();

        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore pre state change listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStorePreStateChange(isDisable ? UserStoreState.DISABLED
                    : UserStoreState.ENABLED, tenantId, domainName);
        }
    }

    /**
     * Trigger the listeners before userstore is added.
     *
     * @param domainName user store domain name.
     * @throws UserStoreException throws when an error occurred when triggering listeners.
     */
    public static void triggerListenersOnUserStorePreAdd(String domainName) throws UserStoreException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();

        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore pre add listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStorePreAdd(tenantId, domainName);
        }
    }

    /**
     * Trigger the listeners after a userstore is retrieved.
     *
     * @param userStoreDTO Retrieved userstore configuration.
     * @throws UserStoreException throws when an error occurred when triggering listeners.
     */
    public static void triggerListenersOnUserStorePostGet(UserStoreDTO userStoreDTO) throws UserStoreException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();

        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore post get listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStorePostGet(tenantId, userStoreDTO);
        }
    }

    /**
     * Trigger the listeners after all userstores are retrieved.
     *
     * @param userStoreDTOS Array of userstore configurations.
     * @throws UserStoreException throws when an error occurred when triggering listeners.
     */
    public static void triggerListenersOnUserStoresPostGet(UserStoreDTO[] userStoreDTOS) throws UserStoreException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();

        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstores post get listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStoresPostGet(tenantId, userStoreDTOS);
        }
    }

    /**
     * Trigger the listeners before a userstore is added.
     *
     * @param userStoreDTO Userstore configuration to be added.
     * @throws UserStoreException throws when an error occurred when triggering listeners.
     */
    public static void triggerListenersOnUserStorePreAdd(UserStoreDTO userStoreDTO) throws UserStoreException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();

        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore pre add listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStorePreAdd(tenantId, userStoreDTO);
        }
    }

    /**
     * Trigger the listeners before a userstore is updated.
     *
     * @param userStoreDTO Userstore configuration to be updated.
     * @param isStateChange Boolean flag denoting whether the
     *                      update is a userstore state change.
     * @throws UserStoreException throws when an error occurred when triggering listeners.
     */
    public static void triggerListenersOnUserStorePreUpdate(UserStoreDTO userStoreDTO, boolean isStateChange)
            throws UserStoreException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<UserStoreConfigListener> userStoreConfigListeners = UserStoreConfigListenersHolder.getInstance()
                .getUserStoreConfigListeners();

        for (UserStoreConfigListener userStoreConfigListener : userStoreConfigListeners) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Triggering userstore pre update listener: %s for tenant: %s",
                        userStoreConfigListener.getClass().getName(),
                        CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
            userStoreConfigListener.onUserStorePreUpdate(tenantId, userStoreDTO, isStateChange);
        }
    }

    /**
     * Checks whether having user stores based on separate repositories are supported.
     *
     * @return True if repository separation is enabled.
     */
    public static boolean isUserStoreRepositorySeparationEnabled() {

        // Support for user stores based on different repositories is
        // disabled as the feature has on going improvements.
        // https://github.com/wso2/product-is/issues/5673
        return false;
    }

    /**
     * Wrap UserStoreClientException in a IdentityUserStoreClientException.
     *
     * @param defaultMessage Default error message.
     * @param e UserStoreClientException.
     * @return new IdentityUserStoreClientException.
     */
    public static IdentityUserStoreClientException buildIdentityUserStoreClientException(String defaultMessage,
                                                                                         UserStoreClientException e) {

        String errorMessage = defaultMessage;
        if (e.getMessage() != null) {
            errorMessage = e.getMessage();
        }
        if (e.getErrorCode() != null) {
            return new IdentityUserStoreClientException(e.getErrorCode(), errorMessage, e);
        }
        return new IdentityUserStoreClientException(errorMessage, e);
    }

    /**
     * Validates the properties of an H2 connection URL. Connection URLs of other drivers are not validated.
     *
     * @param connectionUrl The connection URL to validate.
     * @throws IdentityUserStoreMgtException If the URL carries an escaped semicolon, an unsupported property
     *                                       value, or a property that is not allowed.
     * @deprecated Renamed. Use {@link #validateJdbcConnectionUrl(String)}.
     */
    @Deprecated
    public static void validateConnectionUrlForInitExpressions(String connectionUrl)
            throws IdentityUserStoreMgtException {

        validateJdbcConnectionUrl(connectionUrl);
    }

    /**
     * Validates the properties of an H2 connection URL. Connection URLs of other drivers are not validated.
     *
     * @param connectionUrl The connection URL to validate.
     * @throws IdentityUserStoreMgtException If the URL carries an escaped semicolon, an unsupported property
     *                                       value, or a property that is not allowed.
     */
    public static void validateJdbcConnectionUrl(String connectionUrl)
            throws IdentityUserStoreMgtException {

        if (StringUtils.isBlank(connectionUrl)) {
            return;
        }
        String trimmedUrl = connectionUrl.trim();
        String normalizedUrl = trimmedUrl.toLowerCase(Locale.ENGLISH);

        if (!normalizedUrl.startsWith(H2_URL_PREFIX)) {
            return;
        }

        // Compared in its original case. H2 only reads the lower case mem:, tcp:// and ssl:// forms as non
        // file, so jdbc:h2:MEM: is a file path to H2 and must not be let through as an in memory database.
        if (isFileModeH2Url(trimmedUrl)) {
            throw new IdentityUserStoreClientException("File based JDBC connection URLs are not allowed.");
        }

        if (connectionUrl.contains(ESCAPED_SEMICOLON)) {
            throw new IdentityUserStoreClientException("Escaped semicolons are not allowed in the connection URL.");
        }

        // Everything before the first separator is the database locator, the rest are properties.
        validateH2Properties(connectionUrl.split(CONNECTION_URL_PROPERTY_SEPARATOR), 1);
    }

    /**
     * Validates the properties a user store passes to the driver through the connectionProperties pool setting.
     *
     * H2 reads its settings from the connection URL and from the properties the pool hands the driver, and acts
     * on both the same way. Validating only the URL therefore leaves this as a second route to the same engine,
     * so the settings named here are held to the same rules.
     *
     * @param connectionProperties Value of the connectionProperties user store property. May be null or empty.
     * @param connectionUrl        Connection URL of the same user store, used to scope this to H2.
     * @throws IdentityUserStoreMgtException If a property carries an unsupported value or is not allowed.
     */
    public static void validateConnectionProperties(String connectionProperties, String connectionUrl)
            throws IdentityUserStoreMgtException {

        if (StringUtils.isBlank(connectionProperties) || StringUtils.isBlank(connectionUrl)) {
            return;
        }
        if (!connectionUrl.trim().toLowerCase(Locale.ENGLISH).startsWith(H2_URL_PREFIX)) {
            return;
        }
        // Unlike a connection URL there is no locator to skip, so every segment is a property.
        validateH2Properties(connectionProperties.split(CONNECTION_URL_PROPERTY_SEPARATOR), 0);
    }

    /**
     * Returns the value of a named property, or null when it is not present.
     *
     * Searched from the end, so a name given more than once resolves to the last value. That is the value the
     * realm configuration keeps, and the one the pool will connect with.
     *
     * @param propertyDTOs Properties of the user store.
     * @param propertyName Name to look for, compared ignoring case.
     * @return The property value, or null.
     */
    private static String findPropertyValue(PropertyDTO[] propertyDTOs, String propertyName) {

        for (int i = propertyDTOs.length - 1; i >= 0; i--) {
            PropertyDTO propertyDTO = propertyDTOs[i];
            if (propertyDTO != null && propertyName.equalsIgnoreCase(propertyDTO.getName())) {
                return propertyDTO.getValue();
            }
        }
        return null;
    }

    /**
     * Applies the H2 property rules to name and value pairs taken from a connection URL or from
     * connectionProperties.
     *
     * @param segments   Separator delimited name and value pairs.
     * @param firstIndex Index of the first segment that is a property.
     * @throws IdentityUserStoreMgtException If a property carries an unsupported value or is not allowed.
     */
    private static void validateH2Properties(String[] segments, int firstIndex)
            throws IdentityUserStoreMgtException {

        Set<String> allowedProperties = getAllowedConnectionUrlProperties();

        for (int i = firstIndex; i < segments.length; i++) {
            if (StringUtils.isBlank(segments[i])) {
                continue;
            }
            String property = segments[i].trim();
            int separatorIndex = property.indexOf(CONNECTION_URL_PROPERTY_KEY_VALUE_SEPARATOR);
            String propertyName = separatorIndex < 0 ? property : property.substring(0, separatorIndex);
            propertyName = propertyName.trim();
            String propertyValue = separatorIndex < 0 ? "" : property.substring(separatorIndex + 1).trim();
            // H2 evaluates a property value as an expression, so it has to be restricted to a literal.
            if (!CONNECTION_URL_PROPERTY_VALUE_PATTERN.matcher(propertyValue).matches()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Rejected an unsupported value for the connection property: " + propertyName);
                }
                throw new IdentityUserStoreClientException("The value given for the connection property '"
                        + propertyName + "' is not allowed. Values may contain letters, digits, and the characters "
                        + "_ . , + - only.");
            }
            if (DENIED_PROPERTIES.contains(propertyName.toLowerCase(Locale.ENGLISH))) {
                throw new IdentityUserStoreClientException("The connection property '" + propertyName
                        + "' is never allowed.");
            }
            if (allowedProperties.isEmpty()) {
                // Misconfiguration, already logged. The escaped semicolon and value rules still hold.
                continue;
            }
            if (!allowedProperties.contains(propertyName.toLowerCase(Locale.ENGLISH))) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Rejected a connection property that is not allowed: " + propertyName);
                }
                throw new IdentityUserStoreClientException("The connection property '" + propertyName
                        + "' is not allowed. Allowed properties can be extended through the '"
                        + ALLOWED_CONNECTION_URL_PROPERTY_CONFIG + "' configuration.");
            }
        }
    }

    /**
     * Returns whether an H2 URL is file backed, which would let a connection test create a file anywhere the
     * server can write. The in memory and server forms are the only ones that are not.
     *
     * @param url Trimmed H2 JDBC connection URL in its original case. H2 recognises only the lower case
     *            mem:, tcp:// and ssl:// prefixes, so lower casing before this check would let
     *            jdbc:h2:MEM: pass as in memory while H2 treats it as a file path.
     * @return True if the URL is a file mode database URL.
     */
    private static boolean isFileModeH2Url(String url) {

        return !(url.startsWith(H2_MEMORY_URL_PREFIX)
                || url.startsWith(H2_TCP_URL_PREFIX)
                || url.startsWith(H2_SSL_URL_PREFIX));
    }

    /**
     * Reads the allowed H2 connection URL property names from identity.xml.
     *
     * @return Allowed property names, lower cased. Empty if the configuration is missing.
     */
    private static Set<String> getAllowedConnectionUrlProperties() {

        Set<String> allowedProperties = new HashSet<>();
        for (String property : IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG)) {
            if (StringUtils.isNotBlank(property)) {
                allowedProperties.add(property.trim().toLowerCase(Locale.ENGLISH));
            }
        }
        if (allowedProperties.isEmpty()) {
            LOG.error("No user store connection URL properties are configured under '"
                    + ALLOWED_CONNECTION_URL_PROPERTY_CONFIG + "'. The shipped defaults are missing from "
                    + "identity.xml, so connection URL property names cannot be checked. Escaped semicolons and "
                    + "unsupported property values are still rejected.");
        }
        return allowedProperties;
    }

    /**
     * Checks that a user store validation query is a plain read only statement.
     *
     * A blank query is accepted and leaves the connection pool on its default behaviour. Anything else has to
     * begin with SELECT or VALUES, and may be built only from letters, digits and the characters _ . , * $ and
     * spaces. One trailing semicolon is dropped before the check; a semicolon anywhere else, a parenthesis or a
     * quote fails it, so a value that reaches the pool can neither chain a second statement nor call a function.
     *
     * @param validationQuery The validation query to check. May be null or empty.
     * @throws IdentityUserStoreMgtException If the query is not a plain read only statement.
     */
    public static void validateValidationQuery(String validationQuery) throws IdentityUserStoreMgtException {

        if (StringUtils.isBlank(validationQuery)) {
            return;
        }
        String query = validationQuery.trim();
        // A single trailing semicolon cannot carry a second statement, so it is tolerated for compatibility.
        // Any other semicolon survives and fails the match below.
        if (query.endsWith(STATEMENT_TERMINATOR)) {
            query = query.substring(0, query.length() - STATEMENT_TERMINATOR.length()).trim();
        }
        if (!VALIDATION_QUERY_PATTERN.matcher(query).matches()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Rejected a user store validation query that is not a plain read only statement.");
            }
            // A client exception so the reason reaches the administrator as a 400 instead of a generic 500.
            throw new IdentityUserStoreClientException("The validation query must be a single SELECT or VALUES "
                    + "statement built only from letters, digits and the characters _ . , * $ and spaces.");
        }
    }
}
