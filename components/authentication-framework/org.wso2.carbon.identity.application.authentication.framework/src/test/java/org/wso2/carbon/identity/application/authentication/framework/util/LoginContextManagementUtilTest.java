/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.application.authentication.framework.util;

import org.json.JSONObject;
import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for {@link LoginContextManagementUtil}.
 */
public class LoginContextManagementUtilTest {

    private static final String APPLICATION_NAME = "test-app";
    private static final String PATH_HINT_ACCESS_URL = "https://example.org/t/${UserTenantHint}/home";
    private static final String HOST_HINT_ACCESS_URL = "https://${UserTenantHint}.example.org/home";

    @DataProvider(name = "userTenantHintData")
    public Object[][] userTenantHintData() {

        return new Object[][]{
                // Access URL, ut parameter, t parameter, expected redirect URL.
                {"https://example.org/home", "wso2.com", null, "https://example.org/home"},
                {PATH_HINT_ACCESS_URL, null, "wso2.com", "https://example.org/t/wso2.com/home"},
                {PATH_HINT_ACCESS_URL, "abc-corp", "wso2.com", "https://example.org/t/abc-corp/home"},
                {PATH_HINT_ACCESS_URL, "my_org.handle", null, "https://example.org/t/my_org.handle/home"},
                {PATH_HINT_ACCESS_URL, "WSO2.com", null, "https://example.org/t/WSO2.com/home"},
                {PATH_HINT_ACCESS_URL, "carbon.super", null, "https://example.org/home"},
                {PATH_HINT_ACCESS_URL, null, null, "https://example.org/home"},
                {HOST_HINT_ACCESS_URL, null, "wso2.com", "https://wso2.com.example.org/home"},
                // Hints that are not in a valid tenant domain format are ignored.
                {HOST_HINT_ACCESS_URL, null, "example.com/", "https://carbon.super.example.org/home"},
                {HOST_HINT_ACCESS_URL, "example.com#", "wso2.com", "https://wso2.com.example.org/home"},
                {HOST_HINT_ACCESS_URL, "@example.com", null, "https://carbon.super.example.org/home"},
                {PATH_HINT_ACCESS_URL, null, "../../other", "https://example.org/home"},
                {PATH_HINT_ACCESS_URL, null, "$1", "https://example.org/home"},
        };
    }

    @Test(dataProvider = "userTenantHintData")
    public void testUserTenantHintInRedirectUrl(String accessUrl, String userTenantHint, String loginTenantHint,
                                                String expectedRedirectUrl) throws Exception {

        Map<String, String> params = new HashMap<>();
        params.put("sessionDataKey", "invalid-session-data-key");
        params.put(FrameworkUtils.REQUEST_PARAM_APPLICATION, APPLICATION_NAME);
        params.put("tenantDomain", "carbon.super");
        params.put("ut", userTenantHint);
        params.put("t", loginTenantHint);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter(anyString())).thenAnswer(invocation -> params.get(invocation.getArgument(0)));

        StringWriter responseBody = new StringWriter();
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(responseBody));

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setAccessUrl(accessUrl);
        ApplicationManagementService applicationManagementService = mock(ApplicationManagementService.class);
        when(applicationManagementService.getServiceProvider(APPLICATION_NAME, "carbon.super"))
                .thenReturn(serviceProvider);

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
             MockedStatic<ApplicationManagementService> applicationManagementServiceStatic =
                     mockStatic(ApplicationManagementService.class)) {
            // No authentication context is found for the session data key, so the access URL is returned.
            applicationManagementServiceStatic.when(ApplicationManagementService::getInstance)
                    .thenReturn(applicationManagementService);

            LoginContextManagementUtil.handleLoginContext(request, response);
        }

        JSONObject result = new JSONObject(responseBody.toString());
        assertEquals(result.get("status"), "redirect");
        assertEquals(result.get("redirectUrl"), expectedRedirectUrl);
    }
}
