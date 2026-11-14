package com.acme;

public final class Hello {

    public static void main(String[] args) {
        Greeter greeter = new Greeter("JavaShield");
        System.out.println(greeter.greet());
        System.out.println("sum(1..100)=" + Calculator.sum(1, 100));
        System.out.println("marker=" + Greeter.class.getAnnotation(Marker.class).value());
    }
}
