public class RuntimeExec {
    public void runCommand(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
}
