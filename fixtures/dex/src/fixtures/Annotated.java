package fixtures;

import java.util.List;

/** Fixture for metadata gaps: array-class refs, opcodes, annotations. */
@Meta({"alpha", "beta"})
public class Annotated<T> {
    public int[] copy(int[] values) {
        return values.clone();
    }

    public Meta[] copyMetas(Meta[] metas) {
        return metas.clone();
    }

    public Object make() {
        return new Object();
    }

    public int addOne(int value) {
        return value + 1;
    }

    @Meta({"gamma"})
    public <E> List<E> genericList(List<E> input) {
        return input;
    }
}
