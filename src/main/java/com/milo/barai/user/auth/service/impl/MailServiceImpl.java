package com.milo.barai.user.auth.service.impl;

import com.milo.barai.user.auth.entity.User;
import com.milo.barai.user.auth.exception.UserAuthException;
import com.milo.barai.user.auth.model.Email;
import com.milo.barai.user.auth.model.EmailPreparator;
import com.milo.barai.user.auth.service.MailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import static com.milo.barai.user.auth.exception.UserAuthErrorCode.INTERNAL_ERROR;

@Slf4j
@Service
public class MailServiceImpl implements MailService {

    private static final String VERIFICATION_TEMPLATE = "verificationTemplate";
    private static final String VERIFICATION_TEMPLATE_URL = "verificationURL";

    @Value("${mail.subject.header}")
    private String VerificationSubjectHeader;

    @Value("${mail.application.verification.url}")
    private String VerificationUrl;

    @Value("${mail.application.url}")
    private String ApplicationUrl;

    private final TemplateEngine templateEngine;
    private final JavaMailSender mailSender;

    public MailServiceImpl(TemplateEngine templateEngine,
                           JavaMailSender mailSender) {
        this.templateEngine = templateEngine;
        this.mailSender = mailSender;
    }

    @Async //Don't wait for mail to send.
    @Override
    public void sendVerificationMail(User user, String verificationToken) {

        String body = formatVerificationBody(verificationToken);

        Email mail = new Email(user.getEmail(), VerificationSubjectHeader, body);

        sendMail(mail);
        log.debug("Mail verification was sent to user: {}", user.getId());

    }

    private String formatVerificationBody(String verificationToken) {
        String verificationURL = ApplicationUrl + VerificationUrl + verificationToken;
        Context context = new Context();
        context.setVariable(VERIFICATION_TEMPLATE_URL, verificationURL);
        return templateEngine.process(VERIFICATION_TEMPLATE, context);
    }

    private void sendMail(Email mail) {
        try {
            mailSender.send(new EmailPreparator(mail));
        } catch (MailException e) {
            log.error("Was unable to send verification mail");
            throw new UserAuthException(INTERNAL_ERROR, "Was unable to send email verification", e);
        }
    }

}
