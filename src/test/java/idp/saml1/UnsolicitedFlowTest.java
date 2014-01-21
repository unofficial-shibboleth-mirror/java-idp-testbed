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

package idp.saml1;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.webflow.execution.FlowExecutionOutcome;
import org.springframework.webflow.executor.FlowExecutionResult;
import org.springframework.webflow.executor.FlowExecutor;
import org.springframework.webflow.test.MockExternalContext;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Stub integration test for SAML1 flow.
 */
// TODO context hierarchies ? more annotations ?
@ContextConfiguration({"/system/conf/testbed-ldap.xml", "/system/conf/global-system.xml", "/conf/global-user.xml",
        "/system/conf/mvc-beans.xml", "/conf/webflow-config.xml"})
public class UnsolicitedFlowTest extends AbstractTestNGSpringContextTests {

    /** Flow id. */
    @Nonnull public final static String flowId = "Shibboleth/SSO";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(UnsolicitedFlowTest.class);

    @Test public void testFlow() {
        try {
            // TODO more request parameters
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addParameter("providerId", "https://sp.example.org");

            // TODO use mock contexts from Spring TestContext ?
            HttpServletResponse response = new MockHttpServletResponse();
            MockExternalContext mockCtx = new MockExternalContext();
            mockCtx.setNativeRequest(request);
            mockCtx.setNativeResponse(response);

            // TODO replace with wired-up filter
            HttpServletRequestResponseContext.loadCurrent((HttpServletRequest) request, (HttpServletResponse) response);

            FlowExecutor flowExecutor = applicationContext.getBean("flowExecutor", FlowExecutor.class);

            FlowExecutionResult result = flowExecutor.launchExecution(flowId, null, mockCtx);
            Assert.assertEquals(result.getFlowId(), flowId);

            FlowExecutionOutcome outcome = result.getOutcome();
            log.debug("flow outcome {}", outcome);
            Assert.assertEquals(outcome.getId(), "end");            
            
            // TODO meaningful asserts
            
            Assert.assertTrue(result.isEnded());

        } finally {
            HttpServletRequestResponseContext.clearCurrent();
        }
    }
}
