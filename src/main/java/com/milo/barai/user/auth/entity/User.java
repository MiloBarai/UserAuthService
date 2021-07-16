package com.milo.barai.user.auth.entity;

import lombok.*;

import javax.persistence.*;
import java.util.Date;

@Data
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(unique = true)
    @NonNull
    private String username;

    @Column(unique = true)
    @NonNull
    private String email;

    @NonNull
    private String password;

    //Metadata
    private Date createdAt;
    private boolean enabled;
    private boolean archived;
}
