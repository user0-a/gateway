import javax.tools.ToolProvider;
public class Javac { public static void main(String[] a) { System.exit(ToolProvider.getSystemJavaCompiler().run(null, null, null, a)); } }
