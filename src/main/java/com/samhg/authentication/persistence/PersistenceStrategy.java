package com.samhg.authentication.persistence;

public interface PersistenceStrategy<T, V> {

    V persist(T t);

}