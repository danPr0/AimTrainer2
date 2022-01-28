function validate(input, name, minLength, errorId) {
    let error = document.getElementById(errorId);
    if (input.validity.valueMissing) {
        $(input).addClass("is-invalid");
        $(error).text(name + " is required");
        return false;
    }
    else $(input).removeClass("is-invalid");

    if (input.validity.tooShort) {
        $(input).addClass("is-invalid");
        $(error).text(name+ " must have at least " + minLength + " symbols");
        return false;
    }
    else $(input).removeClass("is-invalid");
}
