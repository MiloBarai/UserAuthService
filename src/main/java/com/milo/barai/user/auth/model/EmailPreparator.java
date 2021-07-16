package com.milo.barai.user.auth.model;
import lombok.NonNull;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;

import javax.mail.internet.MimeMessage;

public class EmailPreparator implements MimeMessagePreparator {

    private static final String FROM_SENDER = "milo.barai.simple-stat@email.com";
    private final Email email;

    public EmailPreparator(Email email) {
        this.email = email;
    }

    @Override
    public void prepare(@NonNull MimeMessage mimeMessage) throws Exception {
        MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
        messageHelper.setFrom(FROM_SENDER);
        messageHelper.setTo(email.getRecipient());
        messageHelper.setSubject(email.getSubject());
        messageHelper.setText(email.getBody(), true);
    }
}
