package com.milo.barai.user.auth.entity;

import lombok.*;

import javax.persistence.*;
import java.util.Date;


@Data
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NonNull
    private String token;

    @OneToOne(fetch = FetchType.LAZY)
    private User user;

    private Date expiryDate;
}
