package com.example.rest;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.Email;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.Size;

import static com.example.constants.RangeConstants.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignUp {
    @Size(min = MIN_USERNAME, max = MAX_USERNAME)
    private String username;

    @Email
    private String email;

    @Size(min = MIN_PASSWORD, max = MAX_PASSWORD)
    private String password;
}
