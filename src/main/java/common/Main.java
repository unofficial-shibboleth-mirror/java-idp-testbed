/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common;

import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.webapp.WebAppContext;

/** Start Jetty */
public class Main {

    /**
     * @param args
     */
    public static void main(String[] args) {

        try {
            Server server = new Server(8080);

            HashLoginService loginService = new HashLoginService();
            loginService.setName("Shib Testbed Web Authentication");
            loginService.setConfig("src/test/config/jetty-realm.properties");
            server.addBean(loginService);

            WebAppContext webapp = new WebAppContext();
            webapp.setContextPath("/");
            webapp.setWar("src/main/webapp");
            server.setHandler(webapp);

            server.start();
            server.join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
