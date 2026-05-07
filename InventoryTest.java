import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

/**
 * Test class for Inventory SQL injection remediation.
 *
 * This test suite validates that the SQL injection vulnerability has been properly
 * fixed by ensuring PreparedStatement is used with parameterized queries instead of
 * string concatenation.
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;

    @BeforeEach
    public void setUp() throws Exception {
        inventory = new Inventory();

        // Mock database objects
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);

        // Set up the mock connection to return our mock PreparedStatement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Inject mock connection into inventory object
        inventory.con = mockConnection;
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
     * This is the primary defense against SQL injection.
     */
    @Test
    public void testUsesPreparedStatementNotStatement() throws Exception {
        // Set up test data with normal input
        setInventoryFields("STYLE001", "VENDOR001", "01/01/2024", "24", "10.5",
                          "Diamond", "2.5", "10", "Test details");

        // Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify PreparedStatement was created (not Statement.executeUpdate with query string)
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );

        // Verify PreparedStatement.executeUpdate was called
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement.executeUpdate was NOT called with concatenated query
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test that SQL injection attempt in style_id field is safely handled.
     * The malicious input should be treated as a literal string parameter.
     */
    @Test
    public void testSqlInjectionInStyleIdIsBlocked() throws Exception {
        // SQL injection attempt: trying to close the quote and add malicious SQL
        String maliciousInput = "STYLE001'); DROP TABLE Inventory; --";

        setInventoryFields(maliciousInput, "VENDOR001", "01/01/2024", "24", "10.5",
                          "Diamond", "2.5", "10", "Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify PreparedStatement was used
        verify(mockConnection).prepareStatement(anyString());

        // Verify the malicious input was set as a parameter (not concatenated into query)
        // This means it will be treated as a literal string, not executed as SQL
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Ensure no raw query execution with concatenated strings
        verify(mockStatement, never()).executeUpdate(contains("DROP TABLE"));
    }

    /**
     * Test that SQL injection attempt in vendor_id field is safely handled.
     */
    @Test
    public void testSqlInjectionInVendorIdIsBlocked() throws Exception {
        String maliciousInput = "VEN001' OR '1'='1";

        setInventoryFields("STYLE001", maliciousInput, "01/01/2024", "24", "10.5",
                          "Diamond", "2.5", "10", "Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify parameterized query was used
        verify(mockPreparedStatement).setString(2, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Ensure the OR condition was not executed as SQL
        verify(mockStatement, never()).executeUpdate(contains("OR '1'='1"));
    }

    /**
     * Test that SQL injection attempt in details field is safely handled.
     */
    @Test
    public void testSqlInjectionInDetailsFieldIsBlocked() throws Exception {
        String maliciousInput = "Test'; DELETE FROM Inventory WHERE '1'='1";

        setInventoryFields("STYLE001", "VENDOR001", "01/01/2024", "24", "10.5",
                          "Diamond", "2.5", "10", maliciousInput);

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify parameterized query was used
        verify(mockPreparedStatement).setString(9, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Ensure DELETE statement was not executed
        verify(mockStatement, never()).executeUpdate(contains("DELETE"));
    }

    /**
     * Test that all nine parameters are correctly set in the PreparedStatement.
     */
    @Test
    public void testAllParametersAreSetCorrectly() throws Exception {
        String styleId = "STYLE123";
        String vendorId = "VENDOR456";
        String inDate = "15/03/2024";
        String goldCr = "22";
        String goldWt = "15.75";
        String stoneType = "Ruby";
        String stoneWt = "3.25";
        String stoneNumber = "15";
        String details = "Premium quality";

        setInventoryFields(styleId, vendorId, inDate, goldCr, goldWt,
                          stoneType, stoneWt, stoneNumber, details);

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all parameters are set in correct order
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
     * Test handling of special characters that could be used in SQL injection.
     */
    @Test
    public void testSpecialCharactersAreHandledSafely() throws Exception {
        // Test various special characters that are dangerous in SQL
        String specialChars = "'; \" \\ -- /* */ %00 %0A";

        setInventoryFields(specialChars, specialChars, "01/01/2024", "24", "10.5",
                          specialChars, "2.5", "10", specialChars);

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify PreparedStatement handles special chars safely
        verify(mockPreparedStatement).setString(1, specialChars);
        verify(mockPreparedStatement).setString(2, specialChars);
        verify(mockPreparedStatement).setString(6, specialChars);
        verify(mockPreparedStatement).setString(9, specialChars);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that empty strings are handled correctly.
     */
    @Test
    public void testEmptyStringsAreHandledCorrectly() throws Exception {
        setInventoryFields("", "", "", "", "", "", "", "", "");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify empty strings are set as parameters
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that very long strings (potential buffer overflow attempts) are handled.
     */
    @Test
    public void testLongStringsAreHandledSafely() throws Exception {
        // Create a very long string
        StringBuilder longString = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longString.append("A");
        }
        String veryLongInput = longString.toString();

        setInventoryFields(veryLongInput, "VENDOR001", "01/01/2024", "24", "10.5",
                          "Diamond", "2.5", "10", veryLongInput);

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify long strings are handled through parameters
        verify(mockPreparedStatement).setString(1, veryLongInput);
        verify(mockPreparedStatement).setString(9, veryLongInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that Unicode characters are handled correctly.
     */
    @Test
    public void testUnicodeCharactersAreHandledSafely() throws Exception {
        String unicodeInput = "测试数据 \u0000 \uFFFF";

        setInventoryFields(unicodeInput, "VENDOR001", "01/01/2024", "24", "10.5",
                          "Diamond", "2.5", "10", unicodeInput);

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify Unicode is handled through parameters
        verify(mockPreparedStatement).setString(1, unicodeInput);
        verify(mockPreparedStatement).setString(9, unicodeInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Helper method to set all inventory text fields.
     */
    private void setInventoryFields(String styleId, String vendorId, String inDate,
                                   String goldCr, String goldWt, String stoneType,
                                   String stoneWt, String stoneNumber, String details) {
        inventory.style_id = createMockTextField(styleId);
        inventory.Vendor_id = createMockTextField(vendorId);
        inventory.in_date = createMockTextField(inDate);
        inventory.gold_cr = createMockTextField(goldCr);
        inventory.gold_wt = createMockTextField(goldWt);
        inventory.stone_type = createMockTextField(stoneType);
        inventory.stone_wt = createMockTextField(stoneWt);
        inventory.stone_number = createMockTextField(stoneNumber);
        inventory.details = createMockTextField(details);
    }

    /**
     * Helper method to create a mock JTextField with specified text.
     */
    private JTextField createMockTextField(String text) {
        JTextField field = mock(JTextField.class);
        when(field.getText()).thenReturn(text);
        return field;
    }
}
