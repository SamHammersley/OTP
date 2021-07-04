package com.samhg.authentication.key;

public interface SharedSecretProvider {

    SharedSecret createSecret();

}