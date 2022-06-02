import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.dbcp2.BasicDataSource;

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

/** Start Jetty */
public class Main {
    private static final String INIT_SQL_HSQLDB="CREATE TABLE StorageRecords (\r\n"
            + "  context varchar(255) NOT NULL,\n"
            + "  id varchar(255) NOT NULL,\n"
            + "  expires bigint DEFAULT NULL,\n"
            + "  value varchar(255) NOT NULL,\n"
            + "  version bigint NOT NULL,\n"
            + "  PRIMARY KEY (context,id)\n"
            + ")";

    /**
     * @param args command-line arguments
     * @throws SQLException 
     */
    public static void main(String[] args) throws SQLException {
        try (final BasicDataSource dataSource = new BasicDataSource()) {
            dataSource.setUrl("jdbc:hsqldb:mem:JPAStorageService;hsqldb.sqllog=3");
            dataSource.setUsername("sa");
            dataSource.setPassword("");
            try (final Connection dbConn = dataSource.getConnection()) {
                final Statement statement = dbConn.createStatement();
                statement.executeUpdate(INIT_SQL_HSQLDB);
            }
        }
        org.eclipse.jetty.start.Main.main(args);
    }

}
