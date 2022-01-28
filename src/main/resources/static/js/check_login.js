jQuery(document).ready(function (){
    if ($("#username").value.length < 2)
        $("#para").append("Username or password are not valid");

    $("#button").click(function () {
        $("#para").append("Username or password are not valid");
    });
});