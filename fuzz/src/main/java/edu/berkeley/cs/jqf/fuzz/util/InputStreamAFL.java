package edu.berkeley.cs.jqf.fuzz.util;

import com.pholser.junit.quickcheck.random.SourceOfRandomness;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class InputStreamAFL extends InputStream {
    private SourceOfRandomness sourceOfRandomness;
    private List<Integer> content = new ArrayList<>();

    public InputStreamAFL(SourceOfRandomness sourceOfRandomness) {
        this.sourceOfRandomness = sourceOfRandomness;
    }

    @Override
    public int read() throws IOException {
        // Keep asking for new random bytes until the
        // SourceOfRandomness runs out of parameters. This is designed
        // to work with fixed-size parameter sequences, such as when
        // fuzzing with AFL.
        try {
            byte nextByte = this.sourceOfRandomness.nextByte(Byte.MIN_VALUE, Byte.MAX_VALUE);
            int nextInt = nextByte & 0xFF;
            this.content.add(nextInt);
            return nextInt;
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof EOFException) {
                return -1;
            } else {
                throw e;
            }
        }
    }

    @Override
    public String toString(){
        return this.content.stream().map(String::valueOf).collect(Collectors.joining(","));
    }
}
