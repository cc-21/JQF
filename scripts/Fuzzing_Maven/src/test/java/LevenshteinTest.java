import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LevenshteinTest {

    @Test
    void getLevenshteinDist() {
        Levenshtein ld = new Levenshtein();
        assertAll(() -> assertEquals(0, ld.getLevenshteinDist("hello", "hello"), "Problem with matching strings"),
                () -> assertEquals(1, ld.getLevenshteinDist("hello", "helo"), "Problem with 1 difference (deletion)"),
                () -> assertEquals(1, ld.getLevenshteinDist("hello", "hallo"), "Problem with 1 difference (substitution)"),
                () -> assertEquals(1, ld.getLevenshteinDist("hello", "helloo"), "Problem with 1 difference (insertion)"),
                () -> assertEquals(2, ld.getLevenshteinDist("hello", "halo"), "Problem with 2 difference (deletion + substitution)"),
                () -> assertEquals(2, ld.getLevenshteinDist("hello", "ohell"), "Problem with 2 difference (deletion + insertion)"),
                () -> assertEquals(2, ld.getLevenshteinDist("hello", "ohallo"), "Problem with 2 difference (substitution + insertion)"),
                () -> assertEquals(3, ld.getLevenshteinDist("hello", "0h@lo"), "Problem with 3 difference (deletion + substitution + insertion)"),
                () -> assertEquals(5, ld.getLevenshteinDist("hello", ""), "Problem with 5 difference (empty string)"));
    }
}