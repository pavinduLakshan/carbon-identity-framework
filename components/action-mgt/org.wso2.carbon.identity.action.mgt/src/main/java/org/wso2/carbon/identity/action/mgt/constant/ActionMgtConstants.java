/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.action.mgt.constant;

/**
 * Constants for Action management service.
 */
public class ActionMgtConstants {

    public static final String ACTIVE_STATUS = "ACTIVE";
    public static final String INACTIVE_STATUS = "INACTIVE";
    public static final String URI_ATTRIBUTE = "uri";
    public static final String AUTHN_TYPE_ATTRIBUTE = "authnType";

    /**
     * Error messages.
     */
    public enum ErrorMessages {

        // Client errors.
        ERROR_CODE_INVALID_ACTION_TYPE("60001", "Invalid action type.",
                "Invalid action type used for path parameter."),

        // Server errors.
        ERROR_CODE_ERROR_WHILE_ADDING_ACTION("65001", "Error while adding Action.",
                "Error while adding Action to the database."),
        ERROR_CODE_ERROR_WHILE_ADDING_ENDPOINT_PROPERTIES("65002",
                "Error while adding Endpoint properties",
                "Error while adding Endpoint properties to the database."),
        ERROR_CODE_ERROR_WHILE_RETRIEVING_ACTION_ENDPOINT_PROPERTIES("65003",
                       "Error while retrieving Action Endpoint properties",
                       "Error while retrieving Action Endpoint properties from the database."),
        ERROR_CODE_ERROR_WHILE_RETRIEVING_ACTIONS_BY_ACTION_TYPE("65004",
                "Error while retrieving Actions by Action Type",
                "Error while retrieving Actions by Action Type from the database."),
        ERROR_CODE_ERROR_WHILE_UPDATING_ENDPOINT_PROPERTIES("65005",
                "Error while updating Action Endpoint properties",
                "Error while updating Action Endpoint properties in the database."),
        ERROR_CODE_ERROR_WHILE_UPDATING_ACTION("65006", "Error while updating Action.",
                "Error while updating Action in the database."),
        ERROR_CODE_ERROR_WHILE_DELETING_ACTION("65007", "Error while deleting Action.",
                "Error while deleting Action from the database."),
        ERROR_CODE_ERROR_WHILE_UPDATING_ACTION_STATUS("65008", "Error while updating Action status.",
                "Error while updating Action status in the database."),
        ERROR_CODE_ERROR_WHILE_RETRIEVING_ACTION_BY_ID("65009", "Error while retrieving Action by ID.",
                "Error while retrieving Action from the database."),
        ERROR_CODE_ERROR_WHILE_RETRIEVING_ACTIONS_COUNT_PER_TYPE("65010",
                "Error while retrieving Actions count per Action Type.",
                "Error while retrieving Actions count from the database.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }
}
