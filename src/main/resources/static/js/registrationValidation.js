function validate() {
    let passwordError = $("<p></p>").text("Password must have at least 8 symbols");
    let passwordMismatchError = $("<p></p>").text("Password mismatch");

    if (document.registrationForm.username.value.length < 4) {
        document.registrationForm.username.focus();
        $("#username").append($("<p></p>").text("Username must have at least 4 symbols"));
        return false;
    }
    else $("#username").clear

    if (document.registrationForm.password.value.length < 8) {
        document.registrationForm.password.focus();
        $("#password").after(passwordError);
        return false;
    }
    else passwordError.remove();

    if (document.registrationForm.password.value === document.registrationForm.passwordConfirm.value) {
        document.registrationForm.passwordConfirm.focus();
        $("#passwordConfirm").after(passwordMismatchError);
        return false;
    }
    else passwordMismatchError.remove();

    $("#registrationButton").submit();
}
