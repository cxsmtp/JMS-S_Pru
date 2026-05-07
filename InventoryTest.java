import org.junit.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive security tests for Inventory class SQL injection remediation.
 *
 * These tests verify that:
 * 1. SQL injection attacks are properly blocked
 * 2. Normal functionality works correctly with parameterized queries
 * 3. Special characters and edge cases are handled safely
 * 4. The vulnerability is not re-introduced through regression
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private JDesktopPane mockDesktop;

    @Before
    public void setUp() throws Exception {
        inventory = new Inventory();
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockDesktop = mock(JDesktopPane.class);

        // Set up the mock connection to return our mock prepared statement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Initialize the inventory frame
        inventory.InventoryFrame(mockDesktop);
    }

    /**
     * Test 1: Verify that SQL injection attempts in vendor ID field are neutralized
     * Attack vector: Classic SQL injection with OR condition
     */
    @Test
    public void testSQLInjectionInVendorIdIsBlocked() throws Exception {
        // Malicious input attempting SQL injection
        String sqlInjectionAttempt = "V001' OR '1'='1";

        inventory.Vendor_id.setText(sqlInjectionAttempt);
        inventory.style_id.setText("S001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test Item");

        // Mock the database connection in the inventory object
        inventory.con = mockConnection;

        // Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify that PreparedStatement was used (not Statement)
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );

        // Verify that the malicious string is passed as a parameter (safely)
        verify(mockPreparedStatement).setString(2, sqlInjectionAttempt);

        // Verify executeUpdate was called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 2: Verify SQL injection with DROP TABLE command is neutralized
     * Attack vector: Attempting to drop a table
     */
    @Test
    public void testSQLInjectionDropTableIsBlocked() throws Exception {
        String dropTableAttempt = "V001'; DROP TABLE Inventory; --";

        inventory.Vendor_id.setText(dropTableAttempt);
        inventory.style_id.setText("S002");
        inventory.in_date.setText("01/02/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("15.0");
        inventory.stone_type.setText("Ruby");
        inventory.stone_wt.setText("3.0");
        inventory.stone_number.setText("3");
        inventory.details.setText("Test Item");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify parameterized query is used
        verify(mockConnection).prepareStatement(contains("?"));

        // Verify the malicious input is treated as data, not SQL code
        verify(mockPreparedStatement).setString(2, dropTableAttempt);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 3: Verify SQL injection in style_id field is blocked
     * Attack vector: Union-based SQL injection
     */
    @Test
    public void testSQLInjectionInStyleIdIsBlocked() throws Exception {
        String unionInjection = "S001' UNION SELECT * FROM Users WHERE '1'='1";

        inventory.style_id.setText(unionInjection);
        inventory.Vendor_id.setText("V001");
        inventory.in_date.setText("01/03/2024");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("20.0");
        inventory.stone_type.setText("Emerald");
        inventory.stone_wt.setText("4.0");
        inventory.stone_number.setText("2");
        inventory.details.setText("Luxury Item");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );
        verify(mockPreparedStatement).setString(1, unionInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 4: Verify SQL injection in details field is blocked
     * Attack vector: Comment-based injection
     */
    @Test
    public void testSQLInjectionInDetailsFieldIsBlocked() throws Exception {
        String commentInjection = "Nice item'); DELETE FROM Inventory WHERE ('1'='1";

        inventory.style_id.setText("S003");
        inventory.Vendor_id.setText("V002");
        inventory.in_date.setText("01/04/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("12.0");
        inventory.stone_type.setText("Sapphire");
        inventory.stone_wt.setText("2.0");
        inventory.stone_number.setText("4");
        inventory.details.setText(commentInjection);

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(9, commentInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 5: Verify normal input with special characters works correctly
     * This ensures the fix doesn't break legitimate use cases
     */
    @Test
    public void testLegitimateSpecialCharactersAreHandledCorrectly() throws Exception {
        inventory.style_id.setText("S-004");
        inventory.Vendor_id.setText("V'Brien & Co.");
        inventory.in_date.setText("01/05/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("8.5");
        inventory.stone_type.setText("Diamond & Ruby");
        inventory.stone_wt.setText("1.5");
        inventory.stone_number.setText("10");
        inventory.details.setText("Special item with 'quotes' and \"double quotes\"");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all parameters are set correctly
        verify(mockPreparedStatement).setString(1, "S-004");
        verify(mockPreparedStatement).setString(2, "V'Brien & Co.");
        verify(mockPreparedStatement).setString(3, "01/05/2024");
        verify(mockPreparedStatement).setString(4, "22");
        verify(mockPreparedStatement).setString(5, "8.5");
        verify(mockPreparedStatement).setString(6, "Diamond & Ruby");
        verify(mockPreparedStatement).setString(7, "1.5");
        verify(mockPreparedStatement).setString(8, "10");
        verify(mockPreparedStatement).setString(9, "Special item with 'quotes' and \"double quotes\"");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 6: Verify empty string inputs are handled correctly
     */
    @Test
    public void testEmptyInputsAreHandledSafely() throws Exception {
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("");
        inventory.stone_wt.setText("");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all empty strings are passed as parameters
        for (int i = 1; i <= 9; i++) {
            verify(mockPreparedStatement).setString(eq(i), eq(""));
        }
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 7: Verify SQL injection with semicolon delimiter is blocked
     * Attack vector: Multiple statement injection
     */
    @Test
    public void testMultipleStatementInjectionIsBlocked() throws Exception {
        String multiStatementInjection = "V003'; UPDATE Inventory SET Gold_wt='0' WHERE '1'='1'; --";

        inventory.style_id.setText("S005");
        inventory.Vendor_id.setText(multiStatementInjection);
        inventory.in_date.setText("01/06/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("5.0");
        inventory.stone_type.setText("Pearl");
        inventory.stone_wt.setText("0.5");
        inventory.stone_number.setText("1");
        inventory.details.setText("Regular item");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the entire malicious string is treated as a parameter value
        verify(mockPreparedStatement).setString(2, multiStatementInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 8: Verify time-based blind SQL injection is neutralized
     * Attack vector: Attempting to use WAITFOR DELAY or SLEEP
     */
    @Test
    public void testTimeBasedBlindSQLInjectionIsBlocked() throws Exception {
        String timeBasedInjection = "V004' OR SLEEP(5) OR '1'='1";

        inventory.style_id.setText("S006");
        inventory.Vendor_id.setText(timeBasedInjection);
        inventory.in_date.setText("01/07/2024");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("25.0");
        inventory.stone_type.setText("Gold");
        inventory.stone_wt.setText("0");
        inventory.stone_number.setText("0");
        inventory.details.setText("Pure gold");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        verify(mockPreparedStatement).setString(2, timeBasedInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 9: Verify PreparedStatement is used instead of Statement
     * This is a regression test to ensure the vulnerability is not reintroduced
     */
    @Test
    public void testPreparedStatementIsUsedNotStatement() throws Exception {
        inventory.style_id.setText("S007");
        inventory.Vendor_id.setText("V005");
        inventory.in_date.setText("01/08/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("7.5");
        inventory.stone_type.setText("Topaz");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("6");
        inventory.details.setText("Normal entry");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify PreparedStatement.prepareStatement was called
        verify(mockConnection).prepareStatement(anyString());

        // Verify Statement.createStatement was NOT called
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test 10: Verify SQL injection with hex encoding attempt is blocked
     * Attack vector: Encoded SQL injection
     */
    @Test
    public void testEncodedSQLInjectionIsBlocked() throws Exception {
        String hexEncodedInjection = "V006' OR 0x31=0x31 --";

        inventory.style_id.setText("S008");
        inventory.Vendor_id.setText(hexEncodedInjection);
        inventory.in_date.setText("01/09/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("9.0");
        inventory.stone_type.setText("Amethyst");
        inventory.stone_wt.setText("2.8");
        inventory.stone_number.setText("7");
        inventory.details.setText("Test");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        verify(mockPreparedStatement).setString(2, hexEncodedInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 11: Verify all 9 parameters are correctly bound
     * This ensures no parameters are missed in the remediation
     */
    @Test
    public void testAllNineParametersAreBoundCorrectly() throws Exception {
        String[] testValues = {
            "StyleTest",
            "VendorTest",
            "DateTest",
            "GoldCaratTest",
            "GoldWeightTest",
            "StoneTypeTest",
            "StoneWeightTest",
            "StoneNumberTest",
            "DetailsTest"
        };

        inventory.style_id.setText(testValues[0]);
        inventory.Vendor_id.setText(testValues[1]);
        inventory.in_date.setText(testValues[2]);
        inventory.gold_cr.setText(testValues[3]);
        inventory.gold_wt.setText(testValues[4]);
        inventory.stone_type.setText(testValues[5]);
        inventory.stone_wt.setText(testValues[6]);
        inventory.stone_number.setText(testValues[7]);
        inventory.details.setText(testValues[8]);

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify each parameter is set in the correct position
        for (int i = 0; i < testValues.length; i++) {
            verify(mockPreparedStatement).setString(i + 1, testValues[i]);
        }

        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 12: Verify SQL keywords in data are treated as literal strings
     */
    @Test
    public void testSQLKeywordsAreTreatedAsLiteralData() throws Exception {
        inventory.style_id.setText("SELECT");
        inventory.Vendor_id.setText("INSERT");
        inventory.in_date.setText("UPDATE");
        inventory.gold_cr.setText("DELETE");
        inventory.gold_wt.setText("DROP");
        inventory.stone_type.setText("CREATE");
        inventory.stone_wt.setText("ALTER");
        inventory.stone_number.setText("WHERE");
        inventory.details.setText("FROM TABLE VALUES");

        inventory.con = mockConnection;

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // All SQL keywords should be treated as literal string data
        verify(mockPreparedStatement).setString(1, "SELECT");
        verify(mockPreparedStatement).setString(2, "INSERT");
        verify(mockPreparedStatement).setString(3, "UPDATE");
        verify(mockPreparedStatement).setString(4, "DELETE");
        verify(mockPreparedStatement).setString(5, "DROP");
        verify(mockPreparedStatement).setString(6, "CREATE");
        verify(mockPreparedStatement).setString(7, "ALTER");
        verify(mockPreparedStatement).setString(8, "WHERE");
        verify(mockPreparedStatement).setString(9, "FROM TABLE VALUES");
        verify(mockPreparedStatement).executeUpdate();
    }

    @After
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockDesktop = null;
    }
}
