import java.sql.Statement;

public class SqlConcat {
    public void runQuery(Statement stmt, String userInput) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput);
    }
}
