function part1(str1) {
    if (str1.length === 5) {
        arr = str1.split("");
        if (
            arr[0] === String.fromCharCode(51) &&
            arr[1] === String.fromCharCode(74) &&
            arr[2] === String.fromCharCode(51) &&
            arr[3] === String.fromCharCode(67) &&
            arr[4] === String.fromCharCode(55)
        )
            return true;
    }
}

function part2(str2) {
    if (str2.length === 4) {
        if (
            str2.charCodeAt(0) +
                2 * str2.charCodeAt(1) -
                3 * str2.charCodeAt(2) +
                4 * str2.charCodeAt(3) ===
                354 &&
            2 * str2.charCodeAt(0) +
                2 * str2.charCodeAt(1) -
                2 * str2.charCodeAt(2) +
                3 * str2.charCodeAt(3) ===
                383 &&
            3 * str2.charCodeAt(0) -
                2 * str2.charCodeAt(1) -
                4 * str2.charCodeAt(2) +
                str2.charCodeAt(3) ===
                -106 &&
            2 * Math.pow(str2.charCodeAt(0), 3) +
                3 * Math.pow(str2.charCodeAt(1), 2) -
                2 * Math.pow(str2.charCodeAt(2), 3) -
                4 * Math.pow(str2.charCodeAt(3), 2) ===
                59284
        )
            return true;
    }
}

function part3(str3, str4, str5, str6) {
    var magic = 0;
    for (var strs of [str3, str4, str5, str6]) {
        if (!/^[01347CFHKLNRUX]+$/g.test(strs)) return false;

        for (var i = 0; i < strs.length; i++) {
            magic = (magic << 3) + strs.charCodeAt(i) - magic;
        }
    }

    if (
        str3.length === 3 &&
        str4.length === 2 &&
        str5.length === 3 &&
        str6.length > 5 &&
        str3[0] === "0" &&
        str5[0] === "7" &&
        str3.charCodeAt(0) + str5.charCodeAt(0) - str6.charCodeAt(0) === 51 &&
        str3.charCodeAt(0) === str4.charCodeAt(0) &&
        str3.charCodeAt(2) - str3.charCodeAt(1) === -30 &&
        (str4.charCodeAt(1) / 7) * str5.charCodeAt(1) === 720 &&
        (str5.charCodeAt(0) + str5.charCodeAt(2) + 2) / 3 === 36 &&
        str6.charCodeAt(3) - str6.charCodeAt(2) === -6 &&
        str6.charCodeAt(2) * str6.charCodeAt(4) === 3936 &&
        magic === -859895409
    )
        return true;
}

function unlock(pwd) {
    var flagSplit = pwd.split("_");
    if (flagSplit.length !== 6) return false;

    if (part1(flagSplit[0])) console.log("Airlock 1 is opened");
    else return false;
    if (part2(flagSplit[1])) console.log("Airlock 2 is opened");
    else return false;
    if (part3(flagSplit[2], flagSplit[3], flagSplit[4], flagSplit[5]))
        console.log("Airlock 3 is opened");
    else return false;

    alert(`Congratulations!\nFlag: STC{${pwd}}`);
}
