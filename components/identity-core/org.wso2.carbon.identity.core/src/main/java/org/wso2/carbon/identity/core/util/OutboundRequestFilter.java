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

import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;

/**
 * Server-level outbound request filter, configured by {@code <OutboundRequestFilter>} in
 * {@code identity.xml}. A destination must clear the blocked hosts and the allowed hosts; with neither
 * configured every URL is allowed. {@link #validate} also checks the scheme.
 */
public final class OutboundRequestFilter {

    private static final Log log = LogFactory.getLog(OutboundRequestFilter.class);

    // The identity.xml element this filter is configured by.
    private static final String CONFIG_OUTBOUND_REQUEST_FILTER = "OutboundRequestFilter";
    private static final String CONFIG_BLOCKED_HOSTS = "BlockedHosts";
    private static final String CONFIG_ALLOWED_HOSTS = "AllowedHosts";
    // Each host list entry is a <Host> element.
    private static final String CONFIG_HOST = "Host";

    // The path each feature enables this filter by.
    private static final String ENFORCE_ACTIONS = "Actions.EnforceOutboundRequestFilter";
    private static final String ENFORCE_WEBHOOKS = "Webhooks.EnforceOutboundRequestFilter";
    private static final String ENFORCE_ADAPTIVE_AUTH = "AdaptiveAuth.EnforceOutboundRequestFilter";
    private static final String ENFORCE_JWKS_ENDPOINT =
            "JWTValidatorConfigs.JWKSEndpoint.EnforceOutboundRequestFilter";
    private static final String ENFORCE_SAML_METADATA_URL =
            "SSOService.MetadataUrl.EnforceOutboundRequestFilter";

    // Stands for any text in a host list entry.
    private static final char WILDCARD = '*';

    // The only schemes allowed. Anything else, such as file, is refused.
    private static final Set<String> ALLOWED_SCHEMES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList("http", "https")));

    static Set<String> blockedHosts = loadHostList(CONFIG_BLOCKED_HOSTS);
    static Set<String> allowedHosts = loadHostList(CONFIG_ALLOWED_HOSTS);

    private OutboundRequestFilter() {

    }

    /**
     * @return {@code true} if action endpoints are checked against this filter.
     */
    public static boolean isEnforcedForActions() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENFORCE_ACTIONS));
    }

    /**
     * @return {@code true} if webhook endpoints are checked against this filter.
     */
    public static boolean isEnforcedForWebhooks() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENFORCE_WEBHOOKS));
    }

    /**
     * @return {@code true} if adaptive authentication endpoints are checked against this filter.
     */
    public static boolean isEnforcedForAdaptiveAuth() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENFORCE_ADAPTIVE_AUTH));
    }

    /**
     * @return {@code true} if a jwks_uri is checked against this filter.
     */
    public static boolean isEnforcedForJwksEndpoint() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENFORCE_JWKS_ENDPOINT));
    }

    /**
     * @return {@code true} if a SAML service provider metadata URL is checked against this filter.
     */
    public static boolean isEnforcedForSamlMetadataUrl() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENFORCE_SAML_METADATA_URL));
    }

    /**
     * @param url The destination URL.
     * @return {@code true} if the request is permitted, {@code false} if it is blocked.
     */
    public static boolean isAllowed(String url) {

        if (blockedHosts.isEmpty() && allowedHosts.isEmpty()) {
            return true;
        }

        String host = extractHost(url);
        if (StringUtils.isBlank(host)) {
            if (log.isDebugEnabled()) {
                log.debug("OutboundRequestFilter blocked an outbound request: the destination URL has no "
                        + "resolvable host.");
            }
            return false;
        }
        host = host.toLowerCase(Locale.ENGLISH);

        if (matchesAny(blockedHosts, host)) {
            if (log.isDebugEnabled()) {
                log.debug("OutboundRequestFilter blocked an outbound request to host [" + host
                        + "]: host is in the configured blocked hosts list.");
            }
            return false;
        }
        if (!allowedHosts.isEmpty() && !matchesAny(allowedHosts, host)) {
            if (log.isDebugEnabled()) {
                log.debug("OutboundRequestFilter blocked an outbound request to host [" + host
                        + "]: host is not in the configured allowed hosts list.");
            }
            return false;
        }
        return true;
    }

    /**
     * @param url The destination.
     * @throws IdentityException if the URL is malformed, the scheme is not http or https, or the
     *                           destination is not permitted.
     */
    public static void validate(String url) throws IdentityException {

        URL parsed;
        try {
            parsed = new URL(url);
        } catch (MalformedURLException e) {
            throw new IdentityException("The destination URL is malformed.");
        }
        String scheme = parsed.getProtocol();
        if (StringUtils.isBlank(scheme) || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ENGLISH))) {
            throw new IdentityException("The destination URL scheme is not one that may be fetched remotely. "
                    + "Only http and https are permitted.");
        }
        if (!isAllowed(url)) {
            throw new IdentityException("The destination is not permitted by the server outbound request "
                    + "filter.");
        }
    }

    /**
     * An entry matches a host literally, or with a single {@code *} standing for any text, so
     * {@code *.example.com} covers its subdomains.
     *
     * @param entries The entries of a host list.
     * @param host    Host taken from the URL, lower-cased.
     * @return {@code true} if the host matches an entry.
     */
    private static boolean matchesAny(Set<String> entries, String host) {

        if (entries.isEmpty() || StringUtils.isBlank(host)) {
            return false;
        }
        for (String entry : entries) {
            int wildcard = entry.indexOf(WILDCARD);
            if (wildcard < 0) {
                if (host.equals(entry)) {
                    return true;
                }
                continue;
            }
            String prefix = entry.substring(0, wildcard);
            String suffix = entry.substring(wildcard + 1);
            if (host.length() >= prefix.length() + suffix.length()
                    && host.startsWith(prefix) && host.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A list that cannot be read is treated as not configured, so a malformed configuration does not
     * change behaviour.
     *
     * @param listName {@code BlockedHosts} or {@code AllowedHosts}.
     * @return The entries, lower-cased, or an empty set.
     */
    private static Set<String> loadHostList(String listName) {

        Set<String> hosts = new HashSet<>();
        try {
            OMElement filterConfig =
                    IdentityConfigParser.getInstance().getConfigElement(CONFIG_OUTBOUND_REQUEST_FILTER);
            if (filterConfig == null) {
                return Collections.unmodifiableSet(hosts);
            }
            OMElement container = filterConfig.getFirstChildWithName(
                    IdentityConfigParser.getInstance().getQNameWithIdentityNS(listName));
            if (container == null) {
                return Collections.unmodifiableSet(hosts);
            }
            Iterator<OMElement> hostElements = container.getChildrenWithName(
                    IdentityConfigParser.getInstance().getQNameWithIdentityNS(CONFIG_HOST));
            while (hostElements != null && hostElements.hasNext()) {
                String value = hostElements.next().getText();
                if (StringUtils.isNotBlank(value)) {
                    hosts.add(value.trim().toLowerCase(Locale.ENGLISH));
                }
            }
        } catch (RuntimeException e) {
            log.error("Failed to load OutboundRequestFilter " + listName + "; treating it as empty.", e);
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(hosts);
    }

    private static String extractHost(String url) {

        if (StringUtils.isBlank(url)) {
            return null;
        }
        try {
            return new URL(url).getHost();
        } catch (MalformedURLException e) {
            return null;
        }
    }
}
