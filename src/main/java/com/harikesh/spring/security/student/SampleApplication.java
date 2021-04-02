package com.harikesh.spring.security.student;

import java.util.function.BiFunction;

public class SampleApplication {
    public static void main(String... args) {
//        BiConsumer<String, String> biConsumer = (x, y) -> System.out.println(x + y);
//        BiConsumer<String, String> biConsumer2 = (var x, final var y) -> System.out.println(x + y);
//        Consumer<String> consumer = System.out::println;
//        BiPredicate<Double, Double> test = (x,y)->Double.isInfinite(x);
//        Consumer con = System.out::println;
//        IntPredicate t = x->x==10;
        String greetings = "Hello";
//        Function<Locale, String> translate = x -> "BONJOUR";
//        System.out.println(translate.apply(Locale.FRENCH));
        BiFunction<Integer, Integer, String> lambda = greetings::substring;
        System.out.println(lambda.apply(1, 3));
    }
}
