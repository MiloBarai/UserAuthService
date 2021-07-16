package com.milo.barai.user.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserTokenDTO {
    private String username;
    private String authenticationToken;
}
