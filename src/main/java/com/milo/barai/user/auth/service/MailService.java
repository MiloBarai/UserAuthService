package com.milo.barai.user.auth.service;

import com.milo.barai.user.auth.entity.User;

public interface MailService {
    void sendVerificationMail(User user, String verificationToken);
}
