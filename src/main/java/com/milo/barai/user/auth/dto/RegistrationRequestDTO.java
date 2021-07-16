package com.milo.barai.user.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NonNull;

import javax.validation.constraints.Email;
import javax.validation.constraints.Size;

@Data
@AllArgsConstructor
public class RegistrationRequestDTO {

    @NonNull
    private String username;

    @NonNull
    private String password;

    @Email
    private String email;
}
