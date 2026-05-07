import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.*;

/**
 * Test class for Inventory SQL injection remediation
 *
 * This test suite verifies that the SQL injection vulnerability has been fixed
 * by ensuring that PreparedStatement is used with parameterized queries instead
 * of string concatenation.
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;

    @BeforeEach
    public void setUp() throws Exception {
        inventory = new Inventory();
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);
    }

    @AfterEach
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
    }

    /**
     * Test that PreparedStatement is used instead of Statement for SQL execution.
     * This verifies the core fix for the SQL injection vulnerability.
     */
    @Test
    public void testUsesParameterizedQuery() throws Exception {
        // Setup: Mock the connection to return a PreparedStatement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Create inventory instance with mocked connection
        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        // Set text field values with normal input
        testInventory.style_id.setText("STYLE001");
        testInventory.Vendor_id.setText("VENDOR001");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        testInventory.details.setText("Test details");

        // Trigger action
        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: PreparedStatement was created with parameterized query
        verify(mockConnection).prepareStatement(contains("?"));
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );
    }

    /**
     * Test that SQL injection attempts in style_id are neutralized.
     * The malicious input should be treated as a literal string value.
     */
    @Test
    public void testSqlInjectionInStyleIdIsBlocked() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        // Malicious input attempting SQL injection
        String maliciousInput = "'); DROP TABLE Inventory; --";
        testInventory.style_id.setText(maliciousInput);
        testInventory.Vendor_id.setText("VENDOR001");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        testInventory.details.setText("Normal details");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: The malicious input is set as a parameter, not concatenated
        verify(mockPreparedStatement).setString(1, maliciousInput);
        // Verify: PreparedStatement executeUpdate is called (not Statement)
        verify(mockPreparedStatement).executeUpdate();
        // Verify: No Statement was created or used
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test that SQL injection attempts in vendor_id are neutralized.
     */
    @Test
    public void testSqlInjectionInVendorIdIsBlocked() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        testInventory.style_id.setText("STYLE001");
        // SQL injection attempt with UNION SELECT
        testInventory.Vendor_id.setText("' UNION SELECT * FROM Users WHERE '1'='1");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        testInventory.details.setText("Normal details");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: Malicious input is treated as parameter
        verify(mockPreparedStatement).setString(2, "' UNION SELECT * FROM Users WHERE '1'='1");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts in details field are neutralized.
     * The details field might contain special characters legitimately.
     */
    @Test
    public void testSqlInjectionInDetailsIsBlocked() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        testInventory.style_id.setText("STYLE001");
        testInventory.Vendor_id.setText("VENDOR001");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        // SQL injection with multiple statements
        testInventory.details.setText("Normal'); DELETE FROM Inventory WHERE '1'='1");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: All parameters are properly set
        verify(mockPreparedStatement).setString(9, "Normal'); DELETE FROM Inventory WHERE '1'='1");
        verify(mockPreparedStatement).executeUpdate();
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test that special characters in input are handled correctly.
     * This ensures functionality is preserved while preventing injection.
     */
    @Test
    public void testSpecialCharactersHandledCorrectly() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        // Legitimate use cases with special characters
        testInventory.style_id.setText("STYLE-001");
        testInventory.Vendor_id.setText("O'Brien & Co.");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22.5");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond (Clarity: VS1)");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        testInventory.details.setText("High quality stone, rated 'A+'");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: All special characters are preserved and set correctly
        verify(mockPreparedStatement).setString(1, "STYLE-001");
        verify(mockPreparedStatement).setString(2, "O'Brien & Co.");
        verify(mockPreparedStatement).setString(6, "Diamond (Clarity: VS1)");
        verify(mockPreparedStatement).setString(9, "High quality stone, rated 'A+'");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that all 9 parameters are properly set in the PreparedStatement.
     * This verifies the complete remediation implementation.
     */
    @Test
    public void testAllParametersAreSet() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        testInventory.style_id.setText("STYLE001");
        testInventory.Vendor_id.setText("VENDOR001");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        testInventory.details.setText("Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: All 9 parameters are set in correct order
        verify(mockPreparedStatement).setString(1, "STYLE001");
        verify(mockPreparedStatement).setString(2, "VENDOR001");
        verify(mockPreparedStatement).setString(3, "01/01/2024");
        verify(mockPreparedStatement).setString(4, "22");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "Diamond");
        verify(mockPreparedStatement).setString(7, "2.5");
        verify(mockPreparedStatement).setString(8, "5");
        verify(mockPreparedStatement).setString(9, "Test details");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that empty or null-like strings are handled correctly.
     */
    @Test
    public void testEmptyStringsHandledCorrectly() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        testInventory.style_id.setText("");
        testInventory.Vendor_id.setText("");
        testInventory.in_date.setText("");
        testInventory.gold_cr.setText("");
        testInventory.gold_wt.setText("");
        testInventory.stone_type.setText("");
        testInventory.stone_wt.setText("");
        testInventory.stone_number.setText("");
        testInventory.details.setText("");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: Empty strings are handled as parameters
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection with quotes in multiple fields simultaneously.
     * This tests a complex attack scenario.
     */
    @Test
    public void testMultipleFieldsWithSqlInjectionAttempts() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        // Multiple fields with injection attempts
        testInventory.style_id.setText("' OR '1'='1");
        testInventory.Vendor_id.setText("'; DROP TABLE Vendors; --");
        testInventory.in_date.setText("01/01/2024' OR '1'='1");
        testInventory.gold_cr.setText("22' UNION SELECT * FROM Users--");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5' OR 1=1--");
        testInventory.details.setText("Normal');DELETE FROM Inventory WHERE('1'='1");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: All malicious inputs are treated as literal string parameters
        verify(mockPreparedStatement).setString(1, "' OR '1'='1");
        verify(mockPreparedStatement).setString(2, "'; DROP TABLE Vendors; --");
        verify(mockPreparedStatement).setString(3, "01/01/2024' OR '1'='1");
        verify(mockPreparedStatement).setString(4, "22' UNION SELECT * FROM Users--");
        verify(mockPreparedStatement).setString(8, "5' OR 1=1--");
        verify(mockPreparedStatement).setString(9, "Normal');DELETE FROM Inventory WHERE('1'='1");
        verify(mockPreparedStatement).executeUpdate();
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test that the query string structure is correct and uses placeholders.
     */
    @Test
    public void testQueryUsesPlaceholders() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        Inventory testInventory = new Inventory() {
            {
                con = mockConnection;
            }
        };

        testInventory.style_id.setText("STYLE001");
        testInventory.Vendor_id.setText("VENDOR001");
        testInventory.in_date.setText("01/01/2024");
        testInventory.gold_cr.setText("22");
        testInventory.gold_wt.setText("10.5");
        testInventory.stone_type.setText("Diamond");
        testInventory.stone_wt.setText("2.5");
        testInventory.stone_number.setText("5");
        testInventory.details.setText("Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);
        testInventory.actionPerformed(mockEvent);

        // Verify: Query contains exactly 9 placeholders
        String expectedQuery = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        verify(mockConnection).prepareStatement(expectedQuery);

        // Count the number of '?' in the query
        long placeholderCount = expectedQuery.chars().filter(ch -> ch == '?').count();
        assertEquals(9, placeholderCount, "Query should contain exactly 9 placeholders");
    }
}
