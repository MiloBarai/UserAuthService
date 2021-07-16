package com.milo.barai.user.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Email {
    private String recipient;
    private String subject;
    private String body;
}
