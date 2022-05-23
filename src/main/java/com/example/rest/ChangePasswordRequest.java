package com.example.rest;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Range;

import javax.validation.constraints.Size;

import static com.example.constants.RangeConstants.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ChangePasswordRequest {
    @Size(min = MIN_PASSWORD, max = MAX_PASSWORD)
    private String oldPassword;

    @Size(min = MIN_PASSWORD, max = MAX_PASSWORD)
    private String newPassword;
}
