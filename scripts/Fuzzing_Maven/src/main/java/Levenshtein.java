public class Levenshtein {
    protected int getLevenshteinDist(String s1, String s2) {
        if (s1.equals(s2)) {
            return 0;
        }
        int n = s2.length();
        int[] v0 = new int[n + 1];
        int[] v1 = new int[n + 1];
        for (int i = 0; i < s2.length() + 1; i++) {
            v0[i] = i;
        }
        for (int i = 0; i < s1.length(); i++) {
            v1[0] = i + 1;
            for (int j = 0; j < s2.length(); j++) {
                int deletionCost = v0[j + 1] + 1;
                int insertionCost = v1[j] + 1;
                int substitutionCost = 0;
                if (s1.charAt(i) == s2.charAt(j)) {
                    substitutionCost = v0[j];
                } else {
                    substitutionCost = v0[j] + 1;
                }
                int min = Math.min(deletionCost, insertionCost);
                v1[j + 1] = Math.min(min, substitutionCost);
            }
            // swap
            int[] tmp = v0;
            v0 = v1;
            v1 = tmp;
        }
        return v0[n];
    }

}
