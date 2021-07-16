package com.milo.barai.user.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class LoginRequestDTO {
    String username;
    String password;
}
