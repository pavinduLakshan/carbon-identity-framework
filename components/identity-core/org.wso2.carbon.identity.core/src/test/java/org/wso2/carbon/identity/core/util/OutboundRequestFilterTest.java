/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.core.util;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BooleanSupplier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Unit tests for {@link OutboundRequestFilter}. The configuration is injected directly into the
 * package-private fields (it is otherwise loaded once from config at class-init).
 */
public class OutboundRequestFilterTest {

    private static Set<String> hosts(String... values) {

        Set<String> set = new HashSet<>();
        Collections.addAll(set, values);
        return set;
    }

    /**
     * The filter reads its configuration once at class initialisation, so a test sets the fields directly.
     */
    private static void policy(Set<String> blocked, Set<String> allowed) {

        OutboundRequestFilter.blockedHosts = blocked;
        OutboundRequestFilter.allowedHosts = allowed;
    }

    @BeforeMethod
    @AfterMethod
    public void resetConfig() {

        policy(Collections.emptySet(), Collections.emptySet());
    }

    private static void blocked(String... entries) {

        policy(hosts(entries), Collections.emptySet());
    }

    private static void allowed(String... entries) {

        policy(Collections.emptySet(), hosts(entries));
    }

    /**
     * Each feature reads its own identity.xml path. The paths are what the configuration templates
     * render, so a change to one on either side has to be made on both.
     */
    @DataProvider(name = "enforcementPaths")
    public Object[][] enforcementPaths() {

        return new Object[][]{
                {"Actions.EnforceOutboundRequestFilter",
                        (BooleanSupplier) OutboundRequestFilter::isEnforcedForActions},
                {"Webhooks.EnforceOutboundRequestFilter",
                        (BooleanSupplier) OutboundRequestFilter::isEnforcedForWebhooks},
                {"AdaptiveAuth.EnforceOutboundRequestFilter",
                        (BooleanSupplier) OutboundRequestFilter::isEnforcedForAdaptiveAuth},
                {"JWTValidatorConfigs.JWKSEndpoint.EnforceOutboundRequestFilter",
                        (BooleanSupplier) OutboundRequestFilter::isEnforcedForJwksEndpoint},
                {"SSOService.MetadataUrl.EnforceOutboundRequestFilter",
                        (BooleanSupplier) OutboundRequestFilter::isEnforcedForSamlMetadataUrl},
        };
    }

    @Test(dataProvider = "enforcementPaths")
    public void testEachFeatureReadsItsOwnPath(String xPath, BooleanSupplier isEnforced) {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(null);
            assertFalse(isEnforced.getAsBoolean(), xPath + " is enforced while it is not configured.");

            identityUtil.when(() -> IdentityUtil.getProperty(xPath)).thenReturn("true");
            assertTrue(isEnforced.getAsBoolean(), xPath + " is not read by its enforcement method.");
        }
    }

    @Test(dataProvider = "enforcementPaths")
    public void testOneFeatureDoesNotEnforceAnother(String xPath, BooleanSupplier isEnforced) {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(anyString())).thenReturn("true");
            identityUtil.when(() -> IdentityUtil.getProperty(xPath)).thenReturn("false");
            assertFalse(isEnforced.getAsBoolean(), xPath + " is enforced by another feature's path.");
        }
    }

    @Test
    public void testEmptyBlocklistAllowsEverything() {

        assertTrue(OutboundRequestFilter.isAllowed("http://127.0.0.1:8899/jwks.json"));
        assertTrue(OutboundRequestFilter.isAllowed("http://169.254.169.254/latest/meta-data/"));
        assertTrue(OutboundRequestFilter.isAllowed("http://localhost/internal"));
        assertTrue(OutboundRequestFilter.isAllowed("not-a-valid-url"));
    }

    @Test
    public void testAbsentConfigurationIsANoOp() {

        // Nothing configured is the shipped default and must allow everything.
        policy(Collections.emptySet(), Collections.emptySet());
        assertTrue(OutboundRequestFilter.isAllowed("http://169.254.169.254/latest/meta-data/"));
        assertTrue(OutboundRequestFilter.isAllowed("http://127.0.0.1:8891/jwks.json"));
    }

    @Test
    public void testBlocklistBlocksOnlyListedHosts() {

        blocked("169.254.169.254", "localhost");
        assertFalse(OutboundRequestFilter.isAllowed("http://169.254.169.254/latest/meta-data/"));
        assertFalse(OutboundRequestFilter.isAllowed("http://localhost/internal"));
        assertTrue(OutboundRequestFilter.isAllowed("https://jwks.example.com/keys"));
    }

    @Test
    public void testBlocklistMatchIsCaseInsensitive() {

        blocked("internal.example.com");
        assertFalse(OutboundRequestFilter.isAllowed("https://INTERNAL.EXAMPLE.COM/keys"));
    }

    @Test
    public void testActiveBlocklistBlocksBlankOrMalformedUrl() {

        blocked("169.254.169.254");
        assertFalse(OutboundRequestFilter.isAllowed(null));
        assertFalse(OutboundRequestFilter.isAllowed(""));
        assertFalse(OutboundRequestFilter.isAllowed("not-a-valid-url"));
    }

    /**
     * The host is matched as it is written in the URL. An entry naming one address does not cover another
     * address in the same range, and covering a range needs a wildcard entry.
     */
    @Test
    public void testListedIpDoesNotBlockADifferentAddressInTheSameRange() {

        blocked("127.0.0.1");
        assertTrue(OutboundRequestFilter.isAllowed("http://127.0.0.2:8891/jwks.json"));

        blocked("127.*");
        assertFalse(OutboundRequestFilter.isAllowed("http://127.0.0.2:8891/jwks.json"));
    }

    @Test
    public void testWildcardEntryMatchesRange() {

        blocked("169.254.*");
        assertFalse(OutboundRequestFilter.isAllowed("http://169.254.169.254/latest/meta-data/"));
        assertFalse(OutboundRequestFilter.isAllowed("http://169.254.1.1/x"));
        assertTrue(OutboundRequestFilter.isAllowed("https://jwks.example.com/keys"));
    }

    @Test
    public void testWildcardEntryMatchesSubdomains() {

        blocked("*.internal.example.com");
        assertFalse(OutboundRequestFilter.isAllowed("https://svc.internal.example.com/keys"));
        assertTrue(OutboundRequestFilter.isAllowed("https://internal.example.com.attacker.test/keys"));
    }

    @Test
    public void testLiteralEntryIsNotTreatedAsRegex() {

        blocked("169.254.169.254");
        assertTrue(OutboundRequestFilter.isAllowed("http://169x254x169x254/x"));
    }

    @Test
    public void testOnlyTheFirstWildcardInAnEntryIsAWildcard() {

        // An entry supports one '*'; any further one is matched literally.
        blocked("10.*");
        assertFalse(OutboundRequestFilter.isAllowed("http://10.1.2.3/x"));
        assertTrue(OutboundRequestFilter.isAllowed("http://11.1.2.3/x"));

        blocked("*.internal.*");
        assertTrue(OutboundRequestFilter.isAllowed("http://svc.internal.example.com/x"));
        assertFalse(OutboundRequestFilter.isAllowed("http://svc.internal.*/x"));
    }

    @Test
    public void testWildcardEntryDoesNotMatchAShorterHost() {

        blocked("*.internal.example.com");
        assertTrue(OutboundRequestFilter.isAllowed("http://internal.example.com/x"));
        assertFalse(OutboundRequestFilter.isAllowed("http://a.internal.example.com/x"));
    }

    @Test
    public void testIpv6EntryIsWrittenTheWayTheUrlCarriesIt() {

        // The host of an IPv6 URL keeps its brackets, so the entry carries them too.
        blocked("[::1]");
        assertFalse(OutboundRequestFilter.isAllowed("http://[::1]:8891/jwks.json"));
    }

    @Test
    public void testUnresolvableHostIsNotNewlyBlocked() {

        blocked("169.254.169.254");
        assertTrue(OutboundRequestFilter.isAllowed("https://no-such-host.invalid/keys"));
    }

    @Test
    public void testPublicDestinationStillAllowedWithActiveBlocklist() {

        blocked("127.0.0.1", "localhost", "169.254.169.254");
        assertTrue(OutboundRequestFilter.isAllowed("https://jwks.example.com/keys"));
    }

    @Test
    public void testAllowlistBlocksEverythingNotListed() {

        allowed("jwks.example.com");
        assertTrue(OutboundRequestFilter.isAllowed("https://jwks.example.com/keys"));
        assertFalse(OutboundRequestFilter.isAllowed("https://other.example.com/keys"));
        assertFalse(OutboundRequestFilter.isAllowed("http://169.254.169.254/latest/meta-data/"));
        assertFalse(OutboundRequestFilter.isAllowed("http://127.0.0.1:8891/jwks.json"));
    }

    @Test
    public void testAllowlistSupportsWildcards() {

        allowed("*.partner.example.com");
        assertTrue(OutboundRequestFilter.isAllowed("https://idp.partner.example.com/keys"));
        assertFalse(OutboundRequestFilter.isAllowed("https://partner.example.com.attacker.test/keys"));
    }

    @Test
    public void testAllowlistMatchIsCaseInsensitive() {

        allowed("jwks.example.com");
        assertTrue(OutboundRequestFilter.isAllowed("https://JWKS.EXAMPLE.COM/keys"));
    }

    @Test
    public void testAllowlistBlocksUnresolvableHostItDoesNotList() {

        allowed("jwks.example.com");
        assertFalse(OutboundRequestFilter.isAllowed("https://no-such-host.invalid/keys"));
    }

    @Test
    public void testBlocklistWinsOverAllowlist() {

        policy(hosts("internal.example.com"), hosts("*.example.com"));
        assertTrue(OutboundRequestFilter.isAllowed("https://jwks.example.com/keys"));
        assertFalse(OutboundRequestFilter.isAllowed("https://internal.example.com/keys"));
    }

    @DataProvider(name = "disallowedSchemes")
    public Object[][] disallowedSchemes() {

        return new Object[][]{
                {"file:///etc/passwd"},
                {"jar:file:///tmp/x.jar!/y.xml"},
                {"ftp://example.com/x"}
        };
    }

    @Test(dataProvider = "disallowedSchemes")
    public void testValidateRejectsDisallowedScheme(String url) {

        assertRefused(url);
    }

    @Test
    public void testValidateRejectsMalformedUrl() {

        assertRefused("not-a-url");
    }

    @Test
    public void testValidateAllowsHttpAndHttpsWhenNothingIsConfigured() throws Exception {

        OutboundRequestFilter.validate("http://example.com/x");
        OutboundRequestFilter.validate("https://example.com/x");
        OutboundRequestFilter.validate("HTTPS://example.com/x");
    }

    @Test
    public void testValidateAppliesTheFilter() throws Exception {

        policy(hosts("169.254.169.254"), Collections.emptySet());
        assertRefused("http://169.254.169.254/latest/");
        OutboundRequestFilter.validate("https://jwks.example.com/keys");
    }

    private void assertRefused(String url) {

        try {
            OutboundRequestFilter.validate(url);
            fail("Expected the destination to be refused: " + url);
        } catch (IdentityException e) {
            assertNotNull(e.getMessage());
        }
    }
}
