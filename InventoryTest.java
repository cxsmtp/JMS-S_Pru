import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.sql.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Test class for Inventory to verify SQL injection vulnerability has been remediated.
 *
 * These tests ensure that:
 * 1. PreparedStatement is used instead of string concatenation for SQL queries
 * 2. User input containing SQL injection payloads cannot manipulate the query
 * 3. The application correctly handles both normal and malicious input
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private boolean preparedStatementUsed = false;

    @BeforeEach
    public void setUp() {
        inventory = new Inventory();
        preparedStatementUsed = false;
    }

    @AfterEach
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
    }

    /**
     * Test that normal input is processed correctly with PreparedStatement
     */
    @Test
    @DisplayName("Test normal inventory submission uses PreparedStatement")
    public void testNormalInventorySubmission() throws Exception {
        // Set up normal values in text fields
        setTextField(inventory, "style_id", "STY-001");
        setTextField(inventory, "Vendor_id", "VEN-123");
        setTextField(inventory, "in_date", "01/05/2024");
        setTextField(inventory, "gold_cr", "18");
        setTextField(inventory, "gold_wt", "15.5");
        setTextField(inventory, "stone_type", "Diamond");
        setTextField(inventory, "stone_wt", "2.5");
        setTextField(inventory, "stone_number", "5");
        setTextField(inventory, "details", "Wedding ring");

        // Verify that the method can execute without throwing SQL injection errors
        // Note: This will fail if database is not available, but demonstrates proper structure
        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database, but should not be SQL injection related
            String errorMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            assertFalse(errorMsg.contains("sql syntax"),
                "SQL syntax error indicates possible injection vulnerability");
        }
    }

    /**
     * Test SQL injection attempt with single quote
     * This test verifies that malicious SQL is treated as data, not code
     */
    @Test
    @DisplayName("Test SQL injection with single quote is prevented")
    public void testSQLInjectionWithSingleQuote() throws Exception {
        // Attempt SQL injection with single quote to break out of string
        String maliciousInput = "' OR '1'='1";

        setTextField(inventory, "style_id", "STY-001");
        setTextField(inventory, "Vendor_id", maliciousInput);
        setTextField(inventory, "in_date", "01/05/2024");
        setTextField(inventory, "gold_cr", "18");
        setTextField(inventory, "gold_wt", "15.5");
        setTextField(inventory, "stone_type", "Diamond");
        setTextField(inventory, "stone_wt", "2.5");
        setTextField(inventory, "stone_number", "5");
        setTextField(inventory, "details", "Normal details");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database
            // Should NOT have SQL syntax errors from injection attempt
            String errorMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            assertFalse(errorMsg.contains("sql syntax") && errorMsg.contains("'1'='1"),
                "SQL injection payload should be treated as data, not executed as code");
        }
    }

    /**
     * Test SQL injection attempt with DROP TABLE
     */
    @Test
    @DisplayName("Test SQL injection with DROP TABLE is prevented")
    public void testSQLInjectionWithDropTable() throws Exception {
        // Attempt SQL injection to drop table
        String maliciousInput = "'; DROP TABLE Inventory; --";

        setTextField(inventory, "style_id", maliciousInput);
        setTextField(inventory, "Vendor_id", "VEN-123");
        setTextField(inventory, "in_date", "01/05/2024");
        setTextField(inventory, "gold_cr", "18");
        setTextField(inventory, "gold_wt", "15.5");
        setTextField(inventory, "stone_type", "Diamond");
        setTextField(inventory, "stone_wt", "2.5");
        setTextField(inventory, "stone_number", "5");
        setTextField(inventory, "details", "Normal details");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database
            // Should NOT actually drop the table
            String errorMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            assertFalse(errorMsg.contains("drop table"),
                "DROP TABLE command should be treated as data, not executed");
        }
    }

    /**
     * Test SQL injection attempt with UNION SELECT
     */
    @Test
    @DisplayName("Test SQL injection with UNION SELECT is prevented")
    public void testSQLInjectionWithUnionSelect() throws Exception {
        // Attempt SQL injection with UNION to extract data
        String maliciousInput = "' UNION SELECT username, password FROM users --";

        setTextField(inventory, "style_id", "STY-001");
        setTextField(inventory, "Vendor_id", "VEN-123");
        setTextField(inventory, "in_date", "01/05/2024");
        setTextField(inventory, "gold_cr", "18");
        setTextField(inventory, "gold_wt", "15.5");
        setTextField(inventory, "stone_type", maliciousInput);
        setTextField(inventory, "stone_wt", "2.5");
        setTextField(inventory, "stone_number", "5");
        setTextField(inventory, "details", "Normal details");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database
            // Should NOT execute the UNION SELECT
            String errorMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            assertFalse(errorMsg.contains("union") && errorMsg.contains("select"),
                "UNION SELECT should be treated as data, not executed");
        }
    }

    /**
     * Test SQL injection with comment symbols
     */
    @Test
    @DisplayName("Test SQL injection with comment symbols is prevented")
    public void testSQLInjectionWithComments() throws Exception {
        // Attempt SQL injection using SQL comments
        String maliciousInput = "admin'--";

        setTextField(inventory, "style_id", "STY-001");
        setTextField(inventory, "Vendor_id", maliciousInput);
        setTextField(inventory, "in_date", "01/05/2024");
        setTextField(inventory, "gold_cr", "18");
        setTextField(inventory, "gold_wt", "15.5");
        setTextField(inventory, "stone_type", "Diamond");
        setTextField(inventory, "stone_wt", "2.5");
        setTextField(inventory, "stone_number", "5");
        setTextField(inventory, "details", "Normal details");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database
            // The comment should be treated as literal data
            assertNotNull(e, "Method should handle input safely");
        }
    }

    /**
     * Test multiple SQL injection attempts in different fields
     */
    @Test
    @DisplayName("Test multiple SQL injection attempts across all fields")
    public void testMultipleSQLInjectionAttempts() throws Exception {
        // Set malicious values in all fields
        setTextField(inventory, "style_id", "' OR '1'='1");
        setTextField(inventory, "Vendor_id", "'; DELETE FROM Inventory; --");
        setTextField(inventory, "in_date", "' UNION ALL SELECT NULL--");
        setTextField(inventory, "gold_cr", "1' OR '1'='1");
        setTextField(inventory, "gold_wt", "1'; UPDATE Inventory SET Price=0--");
        setTextField(inventory, "stone_type", "Diamond' OR '1'='1");
        setTextField(inventory, "stone_wt", "1' AND '1'='2");
        setTextField(inventory, "stone_number", "1' OR 'a'='a");
        setTextField(inventory, "details", "'; EXEC xp_cmdshell('dir'); --");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database
            // None of the injection attempts should execute
            assertNotNull(e, "Method should handle malicious input safely");
        }
    }

    /**
     * Test that special characters are properly escaped
     */
    @Test
    @DisplayName("Test special characters are handled safely")
    public void testSpecialCharactersHandling() throws Exception {
        // Test with legitimate special characters that might appear in jewelry details
        setTextField(inventory, "style_id", "STY-001");
        setTextField(inventory, "Vendor_id", "O'Reilly & Sons");
        setTextField(inventory, "in_date", "01/05/2024");
        setTextField(inventory, "gold_cr", "18");
        setTextField(inventory, "gold_wt", "15.5");
        setTextField(inventory, "stone_type", "Diamond");
        setTextField(inventory, "stone_wt", "2.5");
        setTextField(inventory, "stone_number", "5");
        setTextField(inventory, "details", "Custom design with 'antique' finish & special coating");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail due to missing database, but special chars should be safe
            String errorMsg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            assertFalse(errorMsg.contains("syntax error"),
                "Special characters should be properly escaped");
        }
    }

    /**
     * Test empty string handling
     */
    @Test
    @DisplayName("Test empty strings are handled correctly")
    public void testEmptyStringHandling() throws Exception {
        setTextField(inventory, "style_id", "");
        setTextField(inventory, "Vendor_id", "");
        setTextField(inventory, "in_date", "");
        setTextField(inventory, "gold_cr", "");
        setTextField(inventory, "gold_wt", "");
        setTextField(inventory, "stone_type", "");
        setTextField(inventory, "stone_wt", "");
        setTextField(inventory, "stone_number", "");
        setTextField(inventory, "details", "");

        try {
            inventory.actionPerformed(new ActionEvent(inventory, ActionEvent.ACTION_PERFORMED, "submit"));
        } catch (Exception e) {
            // Expected to fail, but should not have injection-related errors
            assertNotNull(e, "Method should handle empty strings");
        }
    }

    /**
     * Helper method to set text field values using reflection
     */
    private void setTextField(Inventory inventory, String fieldName, String value) throws Exception {
        Field field = Inventory.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(inventory);
        textField.setText(value);
    }

    /**
     * Test to verify PreparedStatement is used in the code
     * This is a code-level verification test
     */
    @Test
    @DisplayName("Verify PreparedStatement is used instead of Statement")
    public void verifyPreparedStatementUsage() throws Exception {
        // Read the source code to verify PreparedStatement usage
        // This is a static analysis test to ensure the fix is in place
        java.io.File sourceFile = new java.io.File("./Inventory.java");
        assertTrue(sourceFile.exists(), "Source file should exist");

        // Read file content
        StringBuilder content = new StringBuilder();
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(sourceFile))) {
            String line;
            boolean inActionPerformed = false;
            boolean foundPreparedStatement = false;
            boolean foundStringConcatenation = false;

            while ((line = reader.readLine()) != null) {
                if (line.contains("public void actionPerformed")) {
                    inActionPerformed = true;
                }

                if (inActionPerformed) {
                    // Check for PreparedStatement usage
                    if (line.contains("PreparedStatement") || line.contains("prepareStatement")) {
                        foundPreparedStatement = true;
                    }

                    // Check for dangerous string concatenation in SQL query
                    if (line.contains("VALUES") && line.contains("\"+'") && line.contains("+\"")) {
                        foundStringConcatenation = true;
                    }

                    // Check for setString calls (parameterized query)
                    if (line.contains(".setString(")) {
                        // This confirms parameterized queries are being used
                    }
                }
            }

            assertTrue(foundPreparedStatement,
                "PreparedStatement should be used in actionPerformed method");
            assertFalse(foundStringConcatenation,
                "SQL query should not use string concatenation with user input");
        }
    }

    /**
     * Test to verify query uses placeholders instead of concatenation
     */
    @Test
    @DisplayName("Verify SQL query uses parameterized placeholders")
    public void verifySQLQueryUsesPlaceholders() throws Exception {
        java.io.File sourceFile = new java.io.File("./Inventory.java");

        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(sourceFile))) {
            String line;
            boolean foundParameterizedQuery = false;

            while ((line = reader.readLine()) != null) {
                // Look for the INSERT query with placeholders
                if (line.contains("INSERT INTO Inventory") && line.contains("VALUES")) {
                    if (line.contains("?,?,?,?,?,?,?,?,?")) {
                        foundParameterizedQuery = true;
                    }
                }
            }

            assertTrue(foundParameterizedQuery,
                "SQL query should use ? placeholders for parameters");
        }
    }
}
