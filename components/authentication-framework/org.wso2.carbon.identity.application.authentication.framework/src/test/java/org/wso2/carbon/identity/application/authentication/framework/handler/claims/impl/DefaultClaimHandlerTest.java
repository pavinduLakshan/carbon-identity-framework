/*
 * Copyright (c) 2023-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authentication.framework.handler.claims.impl;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdPGroup;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class DefaultClaimHandlerTest {

    @Mock
    private AuthenticationContext authenticationContext;
    @Mock
    private SequenceConfig sequenceConfig;
    @Mock
    private ApplicationConfig applicationConfig;
    private static final String testIdP = "testIdP";
    private static final String idpGroupClaimName = "groups";
    private static final String testIdPGroupId = "testIdPGroupId";
    private static final String testIdPGroupName = "admin";
    private static final String applicationId = "testAppId";
    private static final List<String> mappedApplicationRoles =
            new ArrayList<>(Arrays.asList("adminMapped", "hrMapped"));

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetAppAssociatedRolesOfFederatedUser() throws Exception {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {
            DefaultClaimHandler defaultClaimHandler = new DefaultClaimHandler();

            StepConfig stepConfig = new StepConfig();
            stepConfig.setSubjectAttributeStep(true);
            stepConfig.setAuthenticatedIdP(testIdP);
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            stepConfig.setAuthenticatedUser(authenticatedUser);

            ClaimMapping claimMapping = ClaimMapping.build(FrameworkConstants.GROUPS_CLAIM,
                    idpGroupClaimName, null, true, true);
            ClaimMapping[] idPClaimMappings = new ClaimMapping[1];
            idPClaimMappings[0] = claimMapping;

            IdPGroup possibleGroup = new IdPGroup();
            possibleGroup.setIdpGroupId(testIdPGroupId);
            possibleGroup.setIdpGroupName(testIdPGroupName);
            IdPGroup[] idPGroups = new IdPGroup[1];
            idPGroups[0] = possibleGroup;
            IdentityProvider identityProvider = new IdentityProvider();
            identityProvider.setIdPGroupConfig(idPGroups);
            ExternalIdPConfig externalIdPConfig = new ExternalIdPConfig(identityProvider);

            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationResourceId(applicationId);

            when(authenticationContext.getSequenceConfig()).thenReturn(sequenceConfig);
            when(sequenceConfig.getApplicationConfig()).thenReturn(applicationConfig);
            when(applicationConfig.getServiceProvider()).thenReturn(serviceProvider);
            when(authenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);

            frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
            frameworkUtils.when(() -> FrameworkUtils
                                    .getEffectiveIdpGroupClaimUri(eq(stepConfig), eq(authenticationContext)))
                    .thenReturn(idpGroupClaimName);
            when(FrameworkUtils.getAppAssociatedRolesOfFederatedUser(
                    eq(authenticatedUser), eq(applicationId), eq(idpGroupClaimName))).thenReturn(
                    mappedApplicationRoles);

            List<String> applicationRoles =
                    defaultClaimHandler.getAppAssociatedRolesOfFederatedUser(stepConfig, authenticationContext);

            Assert.assertEquals(applicationRoles, mappedApplicationRoles);
        }
    }

    @Test
    public void testGetAppAssociatedRolesOfLocalUser() throws Exception {

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {

            DefaultClaimHandler defaultClaimHandler = new DefaultClaimHandler();

            StepConfig stepConfig = new StepConfig();
            stepConfig.setSubjectAttributeStep(true);
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            stepConfig.setAuthenticatedUser(authenticatedUser);

            ServiceProvider serviceProvider = new ServiceProvider();
            serviceProvider.setApplicationResourceId(applicationId);

            when(authenticationContext.getSequenceConfig()).thenReturn(sequenceConfig);
            when(sequenceConfig.getApplicationConfig()).thenReturn(applicationConfig);
            when(applicationConfig.getServiceProvider()).thenReturn(serviceProvider);

            frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
            frameworkUtils.when(() -> FrameworkUtils
                                    .getAppAssociatedRolesOfLocalUser(eq(authenticatedUser), eq(applicationId)))
                    .thenReturn(mappedApplicationRoles);

            List<String> applicationRoles =
                    defaultClaimHandler.getAppAssociatedRolesOfLocalUser(stepConfig, authenticationContext);

            Assert.assertEquals(applicationRoles, mappedApplicationRoles);
        }
    }

    @Test
    public void testHandleRoleClaimRemovesDomainFromLegacyRoleClaimOnGroupRoleSeparation() throws Exception {

        Map<String, String> mappedAttrs = new HashMap<>();
        mappedAttrs.put(UserCoreConstants.ROLE_CLAIM, "Internal/everyone,SECONDARY/therole");
        mappedAttrs.put(UserCoreConstants.INTERNAL_ROLES_CLAIM, "Internal/everyone");
        mappedAttrs.put(UserCoreConstants.USER_STORE_GROUPS_CLAIM, "therole");
        mappedAttrs.put(FrameworkConstants.USERNAME_CLAIM, "theuser");

        invokeHandleRoleClaim(mappedAttrs, false, true, true, true);

        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.ROLE_CLAIM), "Internal/everyone,therole",
                "User store domain should be removed from the legacy role claim while the hybrid domain is kept.");
        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.INTERNAL_ROLES_CLAIM), "Internal/everyone",
                "Hybrid domains should never be removed from the internal roles claim.");
        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.USER_STORE_GROUPS_CLAIM), "therole",
                "The groups claim should not be touched.");
        Assert.assertEquals(mappedAttrs.get(FrameworkConstants.USERNAME_CLAIM), "theuser",
                "Non role claims should be left untouched.");
    }

    @Test
    public void testHandleRoleClaimRemovesDomainFromLegacyRoleClaimWithoutGroupRoleSeparation() throws Exception {

        Map<String, String> mappedAttrs = new HashMap<>();
        mappedAttrs.put(UserCoreConstants.ROLE_CLAIM, "Internal/everyone,SECONDARY/therole");

        invokeHandleRoleClaim(mappedAttrs, false, false, false, false);

        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.ROLE_CLAIM), "Internal/everyone,therole");
    }

    /**
     * The domain has to be preserved when the application keeps 'Use user store domain in roles' enabled.
     */
    @Test
    public void testHandleRoleClaimKeepsDomainWhenUseUserstoreDomainInRolesEnabled() throws Exception {

        Map<String, String> mappedAttrs = new HashMap<>();
        mappedAttrs.put(UserCoreConstants.ROLE_CLAIM, "Internal/everyone,SECONDARY/therole");

        invokeHandleRoleClaim(mappedAttrs, true, true, true, true);

        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.ROLE_CLAIM), "Internal/everyone,SECONDARY/therole");
    }

    /**
     * The legacy role claim should be left as it is when it is not shown on group vs role separation.
     */
    @Test
    public void testHandleRoleClaimSkipsLegacyRoleClaimWhenNotShown() throws Exception {

        Map<String, String> mappedAttrs = new HashMap<>();
        mappedAttrs.put(UserCoreConstants.ROLE_CLAIM, "Internal/everyone,SECONDARY/therole");

        invokeHandleRoleClaim(mappedAttrs, false, true, false, true);

        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.ROLE_CLAIM), "Internal/everyone,SECONDARY/therole");
    }

    @Test
    public void testHandleRoleClaimKeepsDomainWhenDomainRemovalNotAllowed() throws Exception {

        Map<String, String> mappedAttrs = new HashMap<>();
        mappedAttrs.put(UserCoreConstants.ROLE_CLAIM, "Internal/everyone,SECONDARY/therole");

        invokeHandleRoleClaim(mappedAttrs, false, true, true, false);

        Assert.assertEquals(mappedAttrs.get(UserCoreConstants.ROLE_CLAIM), "Internal/everyone,SECONDARY/therole");
    }

    private void invokeHandleRoleClaim(Map<String, String> mappedAttrs, boolean useUserstoreDomainInRoles,
                                       boolean groupRoleSeparationEnabled, boolean showLegacyRoleClaim,
                                       boolean allowDomainRemovalFromLegacyRoleClaim) throws Exception {

        LocalAndOutboundAuthenticationConfig localAndOutboundConfig = new LocalAndOutboundAuthenticationConfig();
        localAndOutboundConfig.setUseUserstoreDomainInRoles(useUserstoreDomainInRoles);
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundConfig);

        when(authenticationContext.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getApplicationConfig()).thenReturn(applicationConfig);
        when(applicationConfig.getServiceProvider()).thenReturn(serviceProvider);

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class)) {

            identityUtil.when(IdentityUtil::isGroupsVsRolesSeparationImprovementsEnabled)
                    .thenReturn(groupRoleSeparationEnabled);
            identityUtil.when(IdentityUtil::getLocalGroupsClaimURI).thenReturn(groupRoleSeparationEnabled
                    ? UserCoreConstants.INTERNAL_ROLES_CLAIM : UserCoreConstants.ROLE_CLAIM);
            identityUtil.when(IdentityUtil::isShowLegacyRoleClaimOnGroupRoleSeparationEnabled)
                    .thenReturn(showLegacyRoleClaim);
            identityUtil.when(() -> IdentityUtil.getProperty(
                            FrameworkConstants.ALLOW_USERSTORE_DOMAIN_REMOVAL_FROM_LEGACY_ROLE_CLAIM))
                    .thenReturn(String.valueOf(allowDomainRemovalFromLegacyRoleClaim));
            identityUtil.when(() -> IdentityUtil.extractDomainFromName(anyString())).thenCallRealMethod();
            // The separator is resolved from the server configuration, hence it is the only stubbed behaviour.
            frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
            frameworkUtils.when(() -> FrameworkUtils.removeDomainFromNamesExcludeHybrid(any()))
                    .thenCallRealMethod();

            Method handleRoleClaim = DefaultClaimHandler.class
                    .getDeclaredMethod("handleRoleClaim", AuthenticationContext.class, Map.class);
            handleRoleClaim.setAccessible(true);
            handleRoleClaim.invoke(new DefaultClaimHandler(), authenticationContext, mappedAttrs);
        }
    }
}
