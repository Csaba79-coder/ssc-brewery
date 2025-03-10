package guru.sfg.brewery.web.controllers;


import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordEncodingTests {

    static final String PASSWORD = "password";

    @Test
    void hashingExample() {
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));

        String salted = PASSWORD + "ThisIsMySALTVALUE";
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
    }

    @Test
    void testNoOp() {
        PasswordEncoder noOp = NoOpPasswordEncoder.getInstance();
        System.out.println(noOp.encode(PASSWORD));
    }

    @Test
    void testLdap() {
        PasswordEncoder ldap = new LdapShaPasswordEncoder();
        System.out.println(ldap.encode(PASSWORD));
        System.out.println(ldap.encode(PASSWORD)); // this won't 'be the same as before!!! all output is different
        System.out.println(ldap.encode("tiger"));

        String encodedPassword = ldap.encode(PASSWORD);

        assertTrue(ldap.matches(PASSWORD, encodedPassword));
    }

    @Test
    void testSha256() {
        PasswordEncoder sha256 = new StandardPasswordEncoder();

        System.out.println(sha256.encode(PASSWORD));
        System.out.println(sha256.encode(PASSWORD)); // always different values! but the same!
        System.out.println(sha256.encode("password"));

        String encodedSHA256Password = sha256.encode(PASSWORD);

        assertTrue(sha256.matches(PASSWORD, encodedSHA256Password));
    }

    @Test
    void testBCrypt() {
        PasswordEncoder bCrypt = new BCryptPasswordEncoder();

        System.out.println(bCrypt.encode(PASSWORD));
        System.out.println(bCrypt.encode(PASSWORD));
        System.out.println(bCrypt.encode("guru"));

        String bCryptPassword = bCrypt.encode(PASSWORD);

        assertTrue(bCrypt.matches(PASSWORD, bCryptPassword));
    }

    // strength of the hash is 16 here!
    @Test
    void testBCryptStrength() {
        PasswordEncoder bCrypt = new BCryptPasswordEncoder(16); // if it is 12 comes back the result faster! if it is bigger takes longer!

        System.out.println(bCrypt.encode(PASSWORD));
        System.out.println(bCrypt.encode(PASSWORD));

        String bCryptPassword = bCrypt.encode(PASSWORD);

        assertTrue(bCrypt.matches(PASSWORD, bCryptPassword));
    }
}
