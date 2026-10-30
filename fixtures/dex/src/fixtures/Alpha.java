package fixtures;

public class Alpha implements Gamma {
    public static final String TAG = "alpha-tag";
    public static int staticField;
    public long longField;
    private String name;
    public byte[] byteArray;
    public int[][] matrix;

    public Alpha() {
        this.name = "alpha-name";
    }

    static {
        staticField = 7;
    }

    public synchronized void locked() {
        staticField += 1;
    }

    public int add(int a, long b, String text, int[] values) {
        staticField += a;
        longField = b;
        this.name = text;
        int read = staticField;
        return a + read + text.length() + values.length + (int) b;
    }

    public String greet(String who) {
        return "hello " + who + this.name;
    }

    public int helper() {
        return staticField;
    }

    public int duplicateInvokes() {
        return helper() + helper();
    }

    public synchronized int duplicateStrings() {
        String first = "alpha-one";
        String second = "alpha-two";
        String again = "alpha-one";
        return first.length() + second.length() + again.length();
    }

    public long numbers() {
        long big = 1234567890123L;
        double ratio = 3.5;
        int small = 42;
        return big + (long) ratio + small;
    }

    public int fieldTraffic() {
        int readStatic = staticField;
        staticField = readStatic + 1;
        String local = name;
        name = local;
        return readStatic;
    }

    @Override
    public void doIt() {
        add(1, 2L, "call-one", new int[] {1, 2});
        greet("call-two");
        System.out.println(greet("call-three"));
    }
}
