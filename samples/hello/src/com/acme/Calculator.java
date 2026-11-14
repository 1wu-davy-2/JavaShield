package com.acme;

public final class Calculator {

    private Calculator() {
    }

    public static long sum(int from, int to) {
        long total = 0;
        for (int i = from; i <= to; i++) {
            total += i;
        }
        return total;
    }
}
