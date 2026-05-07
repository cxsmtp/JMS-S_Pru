import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.awt.event.ActionEvent;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Test suite for Inventory class SQL injection remediation.
 *
 * This test verifies that the SQL injection vulnerability has been properly fixed
 * by ensuring PreparedStatement is used with parameterized queries instead of
 * string concatenation.
 */
@RunWith(MockitoJUnitRunner.class)
public class InventoryTest {

    private Inventory inventory;

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private ActionEvent mockActionEvent;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        inventory = new Inventory();
    }

    @After
    public void tearDown() {
        inventory = null;
    }

    /**
     * Test that normal input is processed correctly using PreparedStatement.
     * This verifies the basic functionality is preserved after remediation.
     */
    @Test
    public void testNormalInputUsesParameterizedQuery() throws Exception {
        // Setup: Create inventory with normal values
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Beautiful ring");

        // Configure mocks
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Inject mocked connection (in real test, use reflection or dependency injection)
        inventory.con = mockConnection;

        // Execute
        inventory.actionPerformed(mockActionEvent);

        // Verify PreparedStatement is used (not Statement)
        verify(mockConnection).prepareStatement(contains("INSERT INTO Inventory"));
        verify(mockConnection).prepareStatement(contains("?"));

        // Verify all parameters are set correctly
        verify(mockPreparedStatement).setString(1, "STYLE001");
        verify(mockPreparedStatement).setString(2, "VENDOR001");
        verify(mockPreparedStatement).setString(3, "01/01/2024");
        verify(mockPreparedStatement).setString(4, "18");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "Diamond");
        verify(mockPreparedStatement).setString(7, "2.5");
        verify(mockPreparedStatement).setString(8, "5");
        verify(mockPreparedStatement).setString(9, "Beautiful ring");

        // Verify executeUpdate is called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempts are neutralized by PreparedStatement.
     * This test uses a classic SQL injection payload that would succeed with
     * string concatenation but is safely handled by parameterized queries.
     */
    @Test
    public void testSQLInjectionAttemptIsNeutralized() throws Exception {
        // SQL injection payload that would break out of quotes and inject malicious SQL
        String maliciousInput = "'); DROP TABLE Inventory; --";

        // Setup: Inject malicious payload into details field (the vulnerable field)
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(maliciousInput);

        // Configure mocks
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;

        // Execute
        inventory.actionPerformed(mockActionEvent);

        // Verify: The malicious string is passed as a parameter value (9th parameter)
        // and NOT concatenated into the SQL string, which would cause injection
        verify(mockPreparedStatement).setString(9, maliciousInput);

        // Verify the SQL query uses placeholders, not concatenated values
        verify(mockConnection).prepareStatement(argThat(query ->
            query.contains("?") &&
            !query.contains(maliciousInput) &&
            !query.contains("DROP TABLE")
        ));

        // Verify executeUpdate is still called (injection is neutralized, not causing exception)
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection in style_id field (first parameter).
     * Verifies that injection attempts in any field are neutralized.
     */
    @Test
    public void testSQLInjectionInStyleIdField() throws Exception {
        String injectionPayload = "' OR '1'='1";

        inventory.style_id.setText(injectionPayload);
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Normal details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify the injection payload is treated as data, not SQL code
        verify(mockPreparedStatement).setString(1, injectionPayload);
        verify(mockConnection).prepareStatement(argThat(query ->
            !query.contains("OR '1'='1'")
        ));
    }

    /**
     * Test SQL injection with union-based attack.
     * Verifies protection against UNION SELECT injection attempts.
     */
    @Test
    public void testUnionBasedSQLInjectionIsBlocked() throws Exception {
        String unionInjection = "') UNION SELECT username, password FROM users --";

        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(unionInjection);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify UNION attack is treated as literal string data
        verify(mockPreparedStatement).setString(9, unionInjection);
        verify(mockConnection).prepareStatement(argThat(query ->
            !query.contains("UNION SELECT")
        ));
    }

    /**
     * Test that special characters are properly escaped.
     * Verifies that legitimate data containing special SQL characters is handled correctly.
     */
    @Test
    public void testSpecialCharactersAreProperlyHandled() throws Exception {
        // Legitimate data that contains special SQL characters
        String detailsWithSpecialChars = "Ring with 'quote', \"double quote\", and \\ backslash";

        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("O'Brien & Sons"); // Legitimate apostrophe in vendor name
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(detailsWithSpecialChars);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify special characters are passed as-is to PreparedStatement
        // (PreparedStatement handles escaping internally)
        verify(mockPreparedStatement).setString(2, "O'Brien & Sons");
        verify(mockPreparedStatement).setString(9, detailsWithSpecialChars);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that the SQL query structure is correct.
     * Verifies that the parameterized query has the right number of placeholders.
     */
    @Test
    public void testQueryStructureUsesCorrectNumberOfPlaceholders() throws Exception {
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify query has exactly 9 placeholders (?) for 9 parameters
        verify(mockConnection).prepareStatement(argThat(query -> {
            int placeholderCount = query.length() - query.replace("?", "").length();
            return placeholderCount == 9;
        }));
    }

    /**
     * Test SQL injection with encoded characters.
     * Verifies protection against URL-encoded or hex-encoded injection attempts.
     */
    @Test
    public void testEncodedSQLInjectionAttempt() throws Exception {
        // Injection attempt with encoded characters
        String encodedInjection = "%27%29%3B%20DROP%20TABLE%20Inventory%3B%20--";

        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(encodedInjection);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify encoded injection is treated as literal data
        verify(mockPreparedStatement).setString(9, encodedInjection);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that empty strings are handled correctly.
     * Verifies edge case with empty input fields.
     */
    @Test
    public void testEmptyStringHandling() throws Exception {
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("");
        inventory.stone_wt.setText("");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify all empty strings are set as parameters
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection with comment injection.
     * Verifies that comment-based injection attempts are neutralized.
     */
    @Test
    public void testCommentBasedSQLInjection() throws Exception {
        String commentInjection = "test'); -- This should comment out the rest";

        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(commentInjection);

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        inventory.con = mockConnection;
        inventory.actionPerformed(mockActionEvent);

        // Verify comment injection is treated as data
        verify(mockPreparedStatement).setString(9, commentInjection);
        verify(mockConnection).prepareStatement(argThat(query ->
            !query.endsWith("--")
        ));
    }

    /**
     * Test that SQLException is properly handled.
     * Verifies error handling doesn't expose sensitive information.
     */
    @Test
    public void testSQLExceptionHandling() throws Exception {
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenThrow(new SQLException("Database error"));

        inventory.con = mockConnection;

        // Should not throw exception (caught internally)
        try {
            inventory.actionPerformed(mockActionEvent);
        } catch (Exception e) {
            fail("Exception should be caught internally");
        }
    }
}
