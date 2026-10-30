package fixtures;

public class Beta extends Alpha {
    public Beta() {
        super();
    }

    public void run() {
        Alpha alpha = new Alpha();
        alpha.add(3, 4L, "beta-one", new int[] {0});
        String message = alpha.greet("beta-two");
        Alpha.staticField = 21;
        int value = Alpha.staticField;
        System.out.println(message + value);
    }
}
