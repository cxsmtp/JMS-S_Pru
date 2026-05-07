import org.junit.jupiter.api.*;
import org.mockito.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

/**
 * Comprehensive test suite for Inventory class to verify SQL injection vulnerability remediation.
 *
 * This test suite validates that the Inventory class properly uses PreparedStatement
 * with parameterized queries instead of concatenating user input directly into SQL strings.
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;

    @BeforeEach
    public void setUp() throws Exception {
        inventory = new Inventory();
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);

        // Mock the connection creation
        MockedStatic<DriverManager> driverManagerMock = mockStatic(DriverManager.class);
        driverManagerMock.when(() -> DriverManager.getConnection("jdbc:odbc:JMS"))
                         .thenReturn(mockConnection);

        // Mock PreparedStatement creation
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    /**
     * Test 1: Verify that PreparedStatement is used instead of Statement
     * This is the core security fix - parameterized queries prevent SQL injection
     */
    @Test
    public void testUsesPreparedStatementNotStatement() throws Exception {
        // Arrange - Set up text fields with normal data
        setInventoryFields(
            "STYLE001", "VENDOR123", "01/01/2024",
            "24", "15.5", "Diamond", "2.5", "10", "Test item"
        );

        // Act - Trigger the action
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Verify PreparedStatement is created with parameterized query
        verify(mockConnection).prepareStatement(contains("VALUES (?,?,?,?,?,?,?,?,?)"));
        verify(mockConnection, never()).createStatement(); // Should NOT use Statement
    }

    /**
     * Test 2: Verify SQL injection attack is prevented - Single quote injection
     * Tests that malicious input with SQL metacharacters is safely parameterized
     */
    @Test
    public void testPreventsSqlInjectionWithSingleQuotes() throws Exception {
        // Arrange - Malicious input attempting to break out of SQL string
        String maliciousInput = "'; DROP TABLE Inventory; --";
        setInventoryFields(
            maliciousInput, "VENDOR123", "01/01/2024",
            "24", "15.5", "Diamond", "2.5", "10", "Test"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Verify the malicious input is treated as a parameter value, not SQL code
        verify(mockPreparedStatement).setString(1, maliciousInput);
        // The malicious string is passed as data, not executed as SQL
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 3: Verify SQL injection with UNION attack is prevented
     * Tests protection against UNION-based SQL injection attempts
     */
    @Test
    public void testPreventsSqlInjectionWithUnion() throws Exception {
        // Arrange - UNION injection attempt
        String maliciousUnion = "' UNION SELECT * FROM Users WHERE '1'='1";
        setInventoryFields(
            "STYLE001", maliciousUnion, "01/01/2024",
            "24", "15.5", "Diamond", "2.5", "10", "Test"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Malicious UNION is treated as string data
        verify(mockPreparedStatement).setString(2, maliciousUnion);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 4: Verify all parameters are properly bound
     * Ensures all 9 fields are correctly set in the PreparedStatement
     */
    @Test
    public void testAllParametersAreBoundCorrectly() throws Exception {
        // Arrange
        String styleId = "STYLE123";
        String vendorId = "VENDOR456";
        String inDate = "12/31/2024";
        String goldCr = "18";
        String goldWt = "20.5";
        String stoneType = "Ruby";
        String stoneWt = "3.2";
        String stoneNumber = "15";
        String details = "Luxury ring";

        setInventoryFields(styleId, vendorId, inDate, goldCr, goldWt, stoneType, stoneWt, stoneNumber, details);

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Verify each parameter is set in correct order
        verify(mockPreparedStatement).setString(1, styleId);
        verify(mockPreparedStatement).setString(2, vendorId);
        verify(mockPreparedStatement).setString(3, inDate);
        verify(mockPreparedStatement).setString(4, goldCr);
        verify(mockPreparedStatement).setString(5, goldWt);
        verify(mockPreparedStatement).setString(6, stoneType);
        verify(mockPreparedStatement).setString(7, stoneWt);
        verify(mockPreparedStatement).setString(8, stoneNumber);
        verify(mockPreparedStatement).setString(9, details);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 5: Verify SQL injection with comment injection is prevented
     * Tests that SQL comment characters are safely handled
     */
    @Test
    public void testPreventsSqlInjectionWithComments() throws Exception {
        // Arrange - Comment-based injection
        String maliciousComment = "' OR '1'='1' --";
        setInventoryFields(
            "STYLE001", "VENDOR123", "01/01/2024",
            "24", "15.5", maliciousComment, "2.5", "10", "Test"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert
        verify(mockPreparedStatement).setString(6, maliciousComment);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 6: Verify boolean-based SQL injection is prevented
     * Tests OR-based authentication bypass attempts
     */
    @Test
    public void testPreventsBooleanBasedSqlInjection() throws Exception {
        // Arrange - Boolean injection
        String booleanInjection = "1' OR '1'='1";
        setInventoryFields(
            "STYLE001", "VENDOR123", "01/01/2024",
            booleanInjection, "15.5", "Diamond", "2.5", "10", "Test"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert
        verify(mockPreparedStatement).setString(4, booleanInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 7: Verify stacked queries SQL injection is prevented
     * Tests that multiple SQL statements cannot be injected
     */
    @Test
    public void testPreventsStackedQueriesInjection() throws Exception {
        // Arrange - Stacked queries injection
        String stackedQuery = "'; DELETE FROM Inventory WHERE '1'='1";
        setInventoryFields(
            "STYLE001", "VENDOR123", "01/01/2024",
            "24", "15.5", "Diamond", "2.5", stackedQuery, "Test"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Stacked query is safely parameterized
        verify(mockPreparedStatement).setString(8, stackedQuery);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 8: Verify time-based blind SQL injection is prevented
     * Tests that database timing functions are safely handled
     */
    @Test
    public void testPreventsTimeBasedBlindSqlInjection() throws Exception {
        // Arrange - Time-based injection
        String timeBasedInjection = "'; WAITFOR DELAY '00:00:05'--";
        setInventoryFields(
            "STYLE001", "VENDOR123", "01/01/2024",
            "24", "15.5", "Diamond", "2.5", "10", timeBasedInjection
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert
        verify(mockPreparedStatement).setString(9, timeBasedInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 9: Verify special characters are handled safely
     * Tests that various special characters don't break the query
     */
    @Test
    public void testHandlesSpecialCharactersSafely() throws Exception {
        // Arrange - Various special characters
        setInventoryFields(
            "STYLE<>123", "VENDOR&@456", "01/01/2024",
            "24", "15.5", "Diamond\"Test", "2.5", "10\\15", "Detail's & \"quotes\""
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - All special characters are properly escaped/handled by PreparedStatement
        verify(mockPreparedStatement, times(9)).setString(anyInt(), anyString());
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 10: Verify empty strings are handled correctly
     * Tests edge case of empty input fields
     */
    @Test
    public void testHandlesEmptyStringsSafely() throws Exception {
        // Arrange - Empty strings
        setInventoryFields("", "", "", "", "", "", "", "", "");

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Empty strings are valid parameter values
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 11: Verify query structure is correct
     * Ensures the SQL query has the correct parameterized structure
     */
    @Test
    public void testQueryStructureIsParameterized() throws Exception {
        // Arrange
        setInventoryFields(
            "STYLE001", "VENDOR123", "01/01/2024",
            "24", "15.5", "Diamond", "2.5", "10", "Test"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Verify the query uses placeholders (?) instead of concatenated values
        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());

        String capturedQuery = queryCaptor.getValue();
        assertTrue(capturedQuery.contains("VALUES (?,?,?,?,?,?,?,?,?)"),
                   "Query should use parameterized placeholders");
        assertFalse(capturedQuery.matches(".*'\\s*\\+.*"),
                    "Query should not contain string concatenation");
    }

    /**
     * Test 12: Verify functionality with legitimate data containing apostrophes
     * Ensures normal business data with apostrophes works correctly
     */
    @Test
    public void testLegitimateDataWithApostrophesWorks() throws Exception {
        // Arrange - Legitimate data that happens to contain apostrophes
        setInventoryFields(
            "STYLE001", "O'Reilly Vendors", "01/01/2024",
            "24", "15.5", "Diamond", "2.5", "10", "Customer's special order"
        );

        // Act
        inventory.actionPerformed(new ActionEvent(inventory.submit, ActionEvent.ACTION_PERFORMED, "submit"));

        // Assert - Apostrophes in data are handled correctly
        verify(mockPreparedStatement).setString(2, "O'Reilly Vendors");
        verify(mockPreparedStatement).setString(9, "Customer's special order");
        verify(mockPreparedStatement).executeUpdate();
    }

    // Helper method to set all inventory text fields
    private void setInventoryFields(String styleId, String vendorId, String inDate,
                                     String goldCr, String goldWt, String stoneType,
                                     String stoneWt, String stoneNumber, String details) {
        inventory.style_id = createTextField(styleId);
        inventory.Vendor_id = createTextField(vendorId);
        inventory.in_date = createTextField(inDate);
        inventory.gold_cr = createTextField(goldCr);
        inventory.gold_wt = createTextField(goldWt);
        inventory.stone_type = createTextField(stoneType);
        inventory.stone_wt = createTextField(stoneWt);
        inventory.stone_number = createTextField(stoneNumber);
        inventory.details = createTextField(details);
    }

    private JTextField createTextField(String text) {
        JTextField field = new JTextField();
        field.setText(text);
        return field;
    }
}
