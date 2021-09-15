GlobalData = {};
Code_Initializators = [];
GlobalData.WFU = {
    n: []
};
GlobalData.WFUB = {
    n: []
};
GlobalData.filestatematch = {};
GlobalData.filestatematch.success = [0, 1, 2, 2];
GlobalData.filestatematch.warning = [1, 1, 2, 2];
GlobalData.filestatematch.error1 = [3, 3, 2, 3];
GlobalData.filestatematch.error2 = [2, 2, 2, 3];
GlobalData.UploadInProgressString = "";
GlobalData.FreeChangeHandler = false;
wfu_Check_Browser_Capabilities();
if (typeof wfu_js_decode_obj == "undefined")
    wfu_js_decode_obj = function(obj_str) {
        var obj = null;
        if (obj_str == "window")
            obj = window;
        else {
            var dbs = String.fromCharCode(92);
            var match = obj_str.match(new RegExp("GlobalData(" + dbs + ".(WFU|WFUB)" + dbs + "[(.*?)" + dbs + "](" + dbs + ".(.*))?)?$"));
            if (match) {
                obj = GlobalData;
                if (match[3])
                    obj = obj[match[2]][match[3]];
                if (match[5])
                    obj = obj[match[5]]
            }
        }
        return obj
    }
    ;
function wfu_run_js_from_bank() {
    if (typeof WFU_JS_BANK != "undefined")
        while (WFU_JS_BANK.length > 0) {
            var obj = wfu_js_decode_obj(WFU_JS_BANK[0].obj_str);
            if (obj)
                obj[WFU_JS_BANK[0].func].call(obj);
            WFU_JS_BANK.splice(0, 1)
        }
}
function wfu_Initialize_Consts(consts) {
    if (typeof GlobalData.consts != "undefined")
        return;
    GlobalData.consts = new Object;
    var consts_arr = consts.split(";");
    var const_arr;
    for (var i = 0; i < consts_arr.length; i++) {
        const_txt = consts_arr[i].split(":");
        GlobalData.consts[wfu_plugin_decode_string(const_txt[0])] = wfu_plugin_decode_string(const_txt[1])
    }
}
function wfu_Load_Code_Connectors(sid) {
    if (typeof wfu_Code_Objects == "undefined")
        wfu_Code_Objects = {};
    wfu_Code_Objects[sid] = new wfu_Code_Object(sid);
    for (var i = 0; i < Code_Initializators.length; i++)
        wfu_Code_Objects[sid].additem(Code_Initializators[i](sid))
}
function wfu_Code_Object(sid) {
    this.sid = sid;
    this.items = [];
    this._calc_prioritized_list = function(section) {
        var item, list = [], idlist = [], nolist = [], priority;
        for (var i = 0; i < this.items.length; i++) {
            item = this.items[i];
            if (item[section]) {
                priority = -1;
                if (item.priority)
                    priority = item.priority;
                if (item[section].priority)
                    priority = item[section].priority;
                if (priority >= 0) {
                    list.push(priority);
                    idlist.push(i)
                } else
                    nolist.push(i)
            }
        }
        for (var i = 1; i < list.length; i++)
            for (var j = i; j < list.length; j++)
                if (list[j] < list[i - 1]) {
                    var temp = list[j];
                    list[j] = list[i - 1];
                    list[i - 1] = temp;
                    var temp = idlist[j];
                    idlist[j] = idlist[i - 1];
                    idlist[i - 1] = temp
                }
        return idlist.concat(nolist)
    }
    ;
    this.additem = function(item) {
        this.items.push(item)
    }
    ;
    this.apply_filters = function(section, val) {
        if (typeof val == "undefined")
            return null;
        var idlist = this._calc_prioritized_list(section);
        if (idlist.length == 0)
            return val;
        for (var i = 0; i < idlist.length; i++) {
            var item = this.items[idlist[i]];
            var func = null;
            if (typeof item[section] == "function")
                func = item[section];
            else if (typeof item[section].func == "function")
                func = item[section].func;
            if (func != null) {
                val = func.apply(this, Array.prototype.slice.call(arguments, 1));
                arguments[1] = val
            }
        }
        return val
    }
    ;
    this.do_action = function(section) {
        var idlist = this._calc_prioritized_list(section);
        if (idlist.length == 0)
            return;
        for (var i = 0; i < idlist.length; i++) {
            var item = this.items[idlist[i]];
            var func = null;
            if (typeof item[section] == "function")
                func = item[section];
            else if (typeof item[section].func == "function")
                func = item[section].func;
            if (func != null)
                func.apply(this, Array.prototype.slice.call(arguments, 1))
        }
    }
}
function wfu_plugin_load_action(sid) {
    var WFU = GlobalData.WFU[sid];
    wfu_install_unload_hook();
    if (!!WFU.visualeditorbutton_exist) {
        WFU.visualeditorbutton.init();
        var invoke_function = function() {
            wfu_invoke_shortcode_editor(WFU)
        };
        WFU.visualeditorbutton.attachInvokeHandler(invoke_function)
    }
    if (WFU.is_formupload)
        WFU.uploadaction = function() {
            wfu_redirect_to_classic(sid, 0, 0)
        }
        ;
    else
        WFU.uploadaction = function() {
            wfu_HTML5UploadFile(sid)
        }
        ;
    var clickaction = function() {
        wfu_selectbutton_clicked(sid)
    };
    var changeaction = function(fileselected) {
        var WFU = GlobalData.WFU[sid];
        var usefilearray = 0;
        wfu_selectbutton_changed(sid, usefilearray);
        wfu_update_uploadbutton_status(sid);
        if (WFU.singlebutton && fileselected)
            WFU.uploadaction()
    };
    if (!!WFU.uploadform_exist)
        WFU.uploadform.attachActions(clickaction, changeaction);
    var completeaction = function(status) {
        document.getElementById("consentresult_" + sid).value = status
    };
    if (!!WFU.consent_exist) {
        WFU.consent.attachActions(completeaction);
        WFU.consent.update("init")
    }
    if (!!WFU.submit_exist) {
        if (WFU.testmode)
            clickaction = function() {
                alert(GlobalData.consts.notify_testmode)
            }
            ;
        else
            clickaction = function() {
                WFU.uploadaction()
            }
            ;
        WFU.submit.attachClickAction(clickaction)
    }
}
function wfu_install_unload_hook() {
    window.onbeforeunload = wfu_unload_hook
}
function wfu_unload_hook() {
    if (GlobalData.UploadInProgressString != "")
        if (GlobalData.UploadInProgressString.trim() != "")
            return GlobalData.consts.wfu_pageexit_prompt
}
function wfu_Check_Browser_Capabilities() {
    if (typeof wfu_BrowserCaps != "undefined")
        return;
    wfu_BrowserCaps = new Object;
    var xmlhttp = wfu_GetHttpRequestObject();
    wfu_BrowserCaps.supportsAJAX = xmlhttp != null;
    wfu_BrowserCaps.supportsUploadProgress = !!(xmlhttp && "upload"in xmlhttp && "onprogress"in xmlhttp.upload);
    var fd = null;
    try {
        var fd = new FormData
    } catch (e$0) {}
    wfu_BrowserCaps.supportsHTML5 = fd != null;
    var e = document.createElement("iframe");
    wfu_BrowserCaps.supportsIFRAME = e != null;
    wfu_BrowserCaps.supportsDRAGDROP = window.FileReader ? true : false;
    wfu_BrowserCaps.supportsAnimation = wfu_check_animation();
    wfu_BrowserCaps.isSafari = Object.prototype.toString.call(window.HTMLElement).indexOf("Constructor") > 0
}
function wfu_check_animation() {
    var animation = false
      , animationstring = "animation"
      , keyframeprefix = ""
      , domPrefixes = "Webkit Moz O ms Khtml".split(" ")
      , pfx = "";
    var elm = document.createElement("DIV");
    if (elm.style.animationName)
        animation = true;
    if (animation === false)
        for (var i = 0; i < domPrefixes.length; i++)
            if (elm.style[domPrefixes[i] + "AnimationName"] !== undefined) {
                pfx = domPrefixes[i];
                animationstring = pfx + "Animation";
                keyframeprefix = "-" + pfx.toLowerCase() + "-";
                animation = true;
                break
            }
    return animation
}
function wfu_join_strings(delimeter) {
    var args = [].slice.call(arguments);
    var str = "";
    var delim = "";
    for (var i = 1; i < args.length; i++) {
        if (str == "" || args[i] == "")
            delim = "";
        else
            delim = delimeter;
        str += delim + args[i]
    }
    return str
}
function wfu_plugin_decode_string(str) {
    var i = 0;
    var newstr = "";
    var num, val;
    while (i < str.length) {
        num = parseInt(str.substr(i, 2), 16);
        if (num < 128)
            val = num;
        else if (num < 224)
            val = ((num & 31) << 6) + (parseInt(str.substr(i += 2, 2), 16) & 63);
        else
            val = ((num & 15) << 12) + ((parseInt(str.substr(i += 2, 2), 16) & 63) << 6) + (parseInt(str.substr(i += 2, 2), 16) & 63);
        newstr += String.fromCharCode(val);
        i += 2
    }
    return newstr
}
function wfu_plugin_encode_string(str) {
    var i = 0;
    var newstr = "";
    var hex = "";
    for (i = 0; i < str.length; i++) {
        num = str.charCodeAt(i);
        if (num >= 2048)
            num = ((num & 16773120 | 917504) << 4) + ((num & 4032 | 8192) << 2) + (num & 63 | 128);
        else if (num >= 128)
            num = ((num & 65472 | 12288) << 2) + (num & 63 | 128);
        hex = num.toString(16);
        if (hex.length == 1 || hex.length == 3 || hex.length == 5)
            hex = "0" + hex;
        newstr += hex
    }
    return newstr
}
function wfu_decode_array_from_string(str) {
    var arr_str = wfu_plugin_decode_string(str);
    var arr = null;
    try {
        arr = JSON.parse(arr_str)
    } catch (e) {}
    return arr
}
function wfu_randomString(len) {
    var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
    var string_length = len;
    var randomstring = "";
    for (var i = 0; i < string_length; i++) {
        var rnum = Math.floor(Math.random() * chars.length);
        randomstring += chars.substring(rnum, rnum + 1)
    }
    return randomstring
}
function wfu_addEventHandler(obj, evt, handler) {
    if (obj.addEventListener)
        obj.addEventListener(evt, handler, false);
    else if (obj.attachEvent)
        obj.attachEvent("on" + evt, handler);
    else
        obj["on" + evt] = handler
}
function wfu_attach_element_handlers(item, handler) {
    var elem_events = ["DOMAttrModified", "textInput", "input", "change", "keypress", "paste", "focus", "propertychange"];
    for (var i = 0; i < elem_events.length; i++)
        wfu_addEventHandler(item, elem_events[i], handler)
}
function wfu_GetHttpRequestObject() {
    var xhr = null;
    try {
        xhr = new XMLHttpRequest
    } catch (e$1) {
        try {
            xhr = new ActiveXObject("Msxml2.XMLHTTP")
        } catch (e2) {
            try {
                xhr = new ActiveXObject("Microsoft.XMLHTTP")
            } catch (e) {}
        }
    }
    if (xhr == null && window.createRequest)
        try {
            xmlhttp = window.createRequest()
        } catch (e$2) {}
    return xhr
}
function wfu_get_filelist(sid, include_filearray) {
    var WFU = GlobalData.WFU[sid];
    include_filearray = typeof include_filearray !== "undefined" ? include_filearray : true;
    var farr = [];
    if (!!WFU.uploadform_exist)
        farr = WFU.uploadform.files();
    if (include_filearray && typeof WFU.filearray !== "undefined")
        farr = WFU.filearray;
    return farr
}
function wfu_add_files(sid, files) {
    var WFU = GlobalData.WFU[sid];
    if (typeof WFU.filearray == "undefined") {
        WFU.filearray = Array();
        WFU.filearrayprops = Array()
    }
    if (!!WFU.uploadform_exist)
        WFU.uploadform.reset();
    WFU.filearray.length = WFU.filearrayprops.length = 0;
    for (var i = 0; i < files.length; i++) {
        WFU.filearray.push(files[i].file);
        WFU.filearrayprops.push(files[i].props)
    }
}
function wfu_attach_cancel_event(sid, unique_upload_id) {
    function wfu_cancel_classic_upload_final() {
        var Params = wfu_Initialize_Params();
        Params.general.shortcode_id = sid;
        Params.general.unique_id = "";
        Params.general.files_count = 0;
        Params.general.state = 16;
        wfu_ProcessUploadComplete(sid, 0, Params, "no-ajax", "", [false, null, false]);
        if (!!WFU.uploadform_exist) {
            WFU.uploadform.reset();
            WFU.uploadform.submit();
            WFU.uploadform.lock()
        }
    }
    function wfu_cancel_classic_upload() {
        var url = GlobalData.consts.ajax_url + "?action=wfu_ajax_action_cancel_upload&wfu_uploader_nonce=" + document.getElementById("wfu_uploader_nonce_" + sid).value + "&sid=" + sid + "&unique_id=" + unique_upload_id + "&session_token=" + GlobalData.WFU[sid].session;
        var xmlhttp = wfu_GetHttpRequestObject();
        if (xmlhttp == null) {
            var i = document.createElement("iframe");
            if (i) {
                i.style.display = "none";
                i.src = url;
                document.body.appendChild(i);
                i.onload = function() {
                    wfu_cancel_classic_upload_final()
                }
                ;
                return
            }
        }
        xmlhttp.open("GET", url, true);
        xmlhttp.onreadystatechange = function() {
            if (xmlhttp.readyState == 4 && xmlhttp.status == 200)
                wfu_cancel_classic_upload_final()
        }
        ;
        xmlhttp.send(null)
    }
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.textbox_exist) {
        var textbox_cancel_function = function() {
            var answer = false;
            if (WFU.is_formupload) {
                answer = confirm(GlobalData.consts.cancel_upload_prompt);
                if (answer == true)
                    wfu_cancel_classic_upload()
            } else {
                if (!GlobalData[sid] || GlobalData[sid].xhrs.length == 0)
                    return false;
                var answer = confirm(GlobalData.consts.cancel_upload_prompt);
                if (answer == true) {
                    var farr = wfu_get_filelist(sid);
                    var firstxhr = [];
                    var filename = [];
                    for (var i = 0; i < farr.length; i++) {
                        firstxhr.push(null);
                        filename.push(farr[i].name)
                    }
                    for (var i = 0; i < GlobalData[sid].xhrs.length; i++) {
                        var file_ind = GlobalData[sid].xhrs[i].file_id - 1;
                        if (file_ind >= 0 && firstxhr[file_ind] == null)
                            firstxhr[file_ind] = GlobalData[sid].xhrs[i]
                    }
                    if (WFU.debugmode)
                        console.log("upload cancelled!");
                    for (var i = 0; i < firstxhr.length; i++) {
                        if (firstxhr[i] == null) {
                            firstxhr[i] = wfu_GetHttpRequestObject();
                            if (firstxhr[i] != null)
                                wfu_initialize_fileupload_xhr(firstxhr[i], sid, unique_upload_id, i, filename[i])
                        }
                        if (firstxhr[i] != -1) {
                            var evt = {
                                target: {
                                    responseText: "force_cancel_code",
                                    shortcode_id: sid
                                }
                            };
                            wfu_uploadComplete.call(firstxhr[i], evt)
                        }
                    }
                }
            }
            return answer
        };
        WFU.textbox.attachCancelHandler(textbox_cancel_function)
    }
}
function wfu_dettach_cancel_event(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.textbox_exist)
        WFU.textbox.dettachCancelHandler()
}
function wfu_selectbutton_changed(sid, usefilearray) {
    if (!wfu_BrowserCaps.supportsAJAX || !wfu_BrowserCaps.supportsHTML5)
        usefilearray = 0;
    var farr = wfu_get_filelist(sid, false);
    if (usefilearray == 1) {
        if (typeof GlobalData.WFU[sid].filearray == "undefined")
            GlobalData.WFU[sid].filearray = Array();
        for (var i = 0; i < farr.length; i++)
            GlobalData.WFU[sid].filearray.push(farr[i])
    } else if (typeof GlobalData.WFU[sid].filearray != "undefined")
        delete GlobalData.WFU[sid].filearray;
    wfu_update_filename_text(sid)
}
function wfu_selectbutton_clicked(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.message_exist)
        WFU.message.reset();
    var resetform = true;
    if (resetform)
        if (!!WFU.uploadform_exist)
            WFU.uploadform.reset()
}
function wfu_update_uploadbutton_status(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.submit_exist) {
        var submit = WFU.submit;
        var farr = wfu_get_filelist(sid);
        var status = farr.length > 0 || WFU.allownofile;
        status = wfu_Code_Objects[sid].apply_filters("uploadbutton_status", status);
        submit.toggle(status)
    }
}
function wfu_update_filename_text(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.textbox_exist) {
        var farr = wfu_get_filelist(sid);
        var filenames = [];
        for (var i = 0; i < farr.length; i++)
            filenames.push(farr[i].name);
        WFU.textbox.update("set", filenames)
    }
}
function wfu_init_userdata_handlers(sid, key) {
    var WFU = GlobalData.WFU[sid];
    var props = WFU.userdata.props[key];
    var JS = WFU.userdata.codes[key];
    var obj = WFU.userdata;
    JS.init = function() {}
    ;
    JS.value = function() {
        return ""
    }
    ;
    JS.lock = function() {}
    ;
    JS.unlock = function() {}
    ;
    JS.reset = function() {}
    ;
    JS.empty = function() {
        return ""
    }
    ;
    JS.validate = null;
    JS.typehook = null;
    if (props.type == "text") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "multitext") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "number") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                if (props.typehook)
                    JS.typehook(e);
                else
                    props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
        ;
        JS.validate = function() {
            var re = /^(\+|\-)?[0-9]*$/i;
            if (props.format == "f")
                re = /^(\+|\-)?[0-9]*?\.?[0-9]*$/i;
            return re.test(obj.getValue(props)) ? "" : obj.error_invalid_number
        }
        ;
        JS.typehook = function(e) {
            var re = /^(\+|\-)?[0-9]*$/i;
            if (props.format == "f")
                re = /^(\+|\-)?[0-9]*?\.?[0-9]*$/i;
            if (re.test(e.target.value))
                props.store();
            else
                e.target.value = props.getstored()
        }
    } else if (props.type == "email") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
        ;
        JS.validate = function() {
            if (obj.getValue(props) == "")
                return "";
            var re = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i;
            return re.test(obj.getValue(props)) ? "" : obj.error_invalid_email
        }
    } else if (props.type == "confirmemail") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
        ;
        JS.validate = function() {
            var baseprops = null;
            for (var i = 0; i < WFU.userdata.props.length; i++)
                if (WFU.userdata.props[i] && WFU.userdata.props[i].type == "email" && WFU.userdata.props[i].group == props.group) {
                    baseprops = WFU.userdata.props[i];
                    break
                }
            return baseprops != null ? obj.getValue(props) == obj.getValue(baseprops) ? "" : obj.error_confirm_email_nomatch : obj.error_confirm_email_nobase
        }
    } else if (props.type == "password") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "confirmpassword") {
        JS.init = function() {
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
        ;
        JS.validate = function() {
            var baseprops = null;
            for (var i = 0; i < WFU.userdata.props.length; i++)
                if (WFU.userdata.props[i] && WFU.userdata.props[i].type == "password" && WFU.userdata.props[i].group == props.group) {
                    baseprops = WFU.userdata.props[i];
                    break
                }
            return baseprops != null ? obj.getValue(props) == obj.getValue(baseprops) ? "" : obj.error_confirm_password_nomatch : obj.error_confirm_password_nobase
        }
    } else if (props.type == "checkbox") {
        JS.init = function() {
            obj.initField(props);
            obj.setValue(props, props["default"] == "true");
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props) ? "true" : "false"
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"] == "true");
            props.store()
        }
        ;
        JS.empty = function() {
            return !obj.getValue(props) ? obj.error_checkbox_notchecked : ""
        }
    } else if (props.type == "radiobutton") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_radio_notselected : ""
        }
    } else if (props.type == "date") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            def = props["default"].trim();
            if (def.substr(0, 1) == "(" && def.substr(def.length - 1, 1) == ")")
                def = def.substr(1, def.length - 2);
            else
                def = "";
            obj.setValue(props, def);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "time") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            def = props["default"].trim();
            if (def.substr(0, 1) == "(" && def.substr(def.length - 1, 1) == ")")
                def = def.substr(1, def.length - 2);
            else
                def = "";
            obj.setValue(props, def);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "datetime") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            def = props["default"].trim();
            if (def.substr(0, 1) == "(" && def.substr(def.length - 1, 1) == ")")
                def = def.substr(1, def.length - 2);
            else
                def = "";
            obj.setValue(props, def);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "list") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "dropdown") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    } else if (props.type == "honeypot") {
        JS.init = function() {
            obj.initField(props);
            obj.attachHandlers(props, function(e) {
                props.store()
            })
        }
        ;
        JS.value = function() {
            return obj.getValue(props)
        }
        ;
        JS.lock = function() {
            obj.disable(props)
        }
        ;
        JS.unlock = function() {
            obj.enable(props)
        }
        ;
        JS.reset = function() {
            obj.setValue(props, props["default"]);
            props.store()
        }
        ;
        JS.empty = function() {
            return obj.getValue(props) === "" ? obj.error_empty : ""
        }
    }
    JS.init()
}
function wfu_Redirect(link) {
    window.location = link
}
function wfu_loadStart(evt) {}
function wfu_update_upload_metrics(sid) {
    var totalsize = 0;
    var totalloaded = 0;
    var totaldelta = 0;
    var metrics = Array();
    var farr = wfu_get_filelist(sid);
    for (var i = 0; i < farr.length; i++)
        metrics[i] = {
            size: farr[i].size,
            aborted: false,
            loaded: 0,
            delta: 0
        };
    for (var i = 0; i < GlobalData[sid].xhrs.length; i++) {
        var file_id = GlobalData[sid].xhrs[i].file_id;
        if (file_id > 0 && GlobalData[sid].xhrs[i].aborted)
            metrics[file_id - 1].aborted = true
    }
    for (var i = 0; i < GlobalData[sid].xhrs.length; i++) {
        var file_id = GlobalData[sid].xhrs[i].file_id;
        if (file_id > 0 && !metrics[file_id - 1].aborted) {
            metrics[file_id - 1].size = Math.max(GlobalData[sid].xhrs[i].totalsize, metrics[file_id - 1].size);
            metrics[file_id - 1].loaded += GlobalData[sid].xhrs[i].sizeloaded;
            metrics[file_id - 1].delta += Math.max(GlobalData[sid].xhrs[i].deltaloaded, 0)
        }
    }
    for (var i = 0; i < farr.length; i++) {
        var Gm = GlobalData[sid].metrics[i];
        if (!metrics[i].aborted && metrics[i].size > 0) {
            Gm.size = metrics[i].size;
            if (GlobalData.consts.wfu_uploadprogress_mode == "incremental")
                Gm.progress_pos = Math.min(Gm.progress_pos + (1 - Gm.progress_pos) * metrics[i].delta / (Gm.size - Gm.loaded), 1);
            else
                Gm.progress_pos = metrics[i].loaded / metrics[i].size;
            Gm.loaded = metrics[i].loaded;
            totalsize += Gm.size;
            totalloaded += Gm.loaded;
            totaldelta += metrics[i].delta
        } else {
            Gm.size = 0;
            Gm.progress_pos = 0;
            Gm.loaded = 0
        }
    }
    var Gm = GlobalData[sid].metricstotal;
    Gm.size = totalsize;
    if (GlobalData.consts.wfu_uploadprogress_mode == "incremental")
        Gm.progress_pos = Math.min(Gm.progress_pos + (1 - Gm.progress_pos) * totaldelta / (Gm.size - Gm.loaded), 1);
    else
        Gm.progress_pos = totalloaded / totalsize;
    Gm.loaded = totalloaded
}
function wfu_uploadProgress(evt, sid, xhrid, debugmode) {
    var WFU = GlobalData.WFU[sid];
    if (debugmode && typeof this.xhr == "undefined") {
        console.log("total=" + evt.total + ", loaded=" + evt.loaded);
        console.log(evt)
    }
    var this_xhr = GlobalData[sid].xhrs[xhrid];
    if (this_xhr.file_id == 0)
        return;
    var percentComplete = 0;
    var delta = 0;
    var simplebar_exists = !!WFU.progressbar_exist;
    if (evt.lengthComputable) {
        this_xhr.deltaloaded = evt.loaded - this_xhr.sizeloaded;
        this_xhr.sizeloaded = evt.loaded;
        if (this_xhr.size < evt.total && evt.total > 0) {
            delta = evt.total - this_xhr.size;
            this_xhr.deltasize += delta;
            this_xhr.size += delta;
            for (var i = 0; i < GlobalData[sid].xhrs.length; i++)
                if (GlobalData[sid].xhrs[i].file_id == this_xhr.file_id)
                    GlobalData[sid].xhrs[i].totalsize += delta
        }
        wfu_update_upload_metrics(sid);
        this_xhr.deltaloaded = 0;
        if (simplebar_exists) {
            percentComplete = Math.round(GlobalData[sid].metricstotal.progress_pos * 100);
            WFU.progressbar.update(percentComplete)
        }
    } else if (simplebar_exists)
        WFU.progressbar.update(0)
}
function wfu_notify_WPFilebase(params_index, session_token) {
    var xhr = wfu_GetHttpRequestObject();
    if (xhr == null) {
        var i = document.createElement("iframe");
        i.style.display = "none";
        i.src = GlobalData.consts.ajax_url + "?action=wfu_ajax_action_notify_wpfilebase&params_index=" + params_index + "&session_token=" + session_token;
        document.body.appendChild(i);
        return
    }
    var url = GlobalData.consts.ajax_url;
    params = new Array(3);
    params[0] = new Array(2);
    params[0][0] = "action";
    params[0][1] = "wfu_ajax_action_notify_wpfilebase";
    params[1] = new Array(2);
    params[1][0] = "params_index";
    params[1][1] = params_index;
    params[2] = new Array(2);
    params[2][0] = "session_token";
    params[2][1] = session_token;
    var parameters = "";
    for (var i = 0; i < params.length; i++)
        parameters += (i > 0 ? "&" : "") + params[i][0] + "=" + encodeURI(params[i][1]);
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {}
    ;
    xhr.send(parameters)
}
function wfu_send_email_notification(sid, unique_id) {
    var WFU = GlobalData.WFU[sid];
    var xhr = wfu_GetHttpRequestObject();
    if (xhr == null)
        return;
    var url = GlobalData.consts.ajax_url;
    params = new Array(4);
    params[0] = new Array(2);
    params[0][0] = "action";
    params[0][1] = "wfu_ajax_action_send_email_notification";
    params[1] = new Array(2);
    params[1][0] = "params_index";
    params[1][1] = WFU.params_index;
    params[2] = new Array(2);
    params[2][0] = "session_token";
    params[2][1] = WFU.session;
    params[3] = new Array(2);
    params[3][0] = "uniqueuploadid_" + sid;
    params[3][1] = unique_id;
    var parameters = "";
    for (var i = 0; i < params.length; i++)
        parameters += (i > 0 ? "&" : "") + params[i][0] + "=" + encodeURI(params[i][1]);
    wfu_initialize_fileupload_xhr(xhr, sid, unique_id, -1, "");
    xhr.success_message_header = "";
    xhr.error_message_header = "";
    xhr.error_adminmessage_unknown = "";
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.addEventListener("load", wfu_uploadComplete, false);
    xhr.addEventListener("error", wfu_uploadFailed, false);
    xhr.addEventListener("abort", wfu_uploadCanceled, false);
    xhr.send(parameters)
}
function wfu_uploadComplete(evt) {
    var d = new Date;
    var sid = this.shortcode_id;
    var WFU = GlobalData.WFU[sid];
    var i = this.file_id;
    var last = false;
    var js_script_enc = "";
    var upload_params = "";
    var safe_params = "";
    var file_status = "unknown";
    var uploaded_file_props = "";
    var debug_data = null;
    var success_txt = "wfu_fileupload_success:";
    this.loading = false;
    this.end_time = d.getTime();
    var txt = evt.target.responseText;
    var result_data = txt;
    var error_code = "error";
    if (txt != -1) {
        if (txt.indexOf("force_errorabort_code") > -1) {
            error_code = "errorabort";
            txt = txt.replace("force_errorabort_code", "")
        }
        if (txt.indexOf("force_cancel_code") > -1) {
            error_code = "errorcancel";
            txt = txt.replace("force_cancel_code", "")
        }
        if (txt.indexOf("force_abortsuccess_code") > -1) {
            error_code = "errorabortsuccess";
            txt = txt.replace("force_abortsuccess_code", "")
        }
    }
    if (txt != -1) {
        var pos = txt.indexOf(success_txt);
        var debug_data_str = "";
        if (pos > -1) {
            if (WFU.debugmode)
                debug_data_str = txt.substr(0, pos);
            result_data = txt.substr(pos + success_txt.length);
            pos = result_data.indexOf(":");
            js_script_enc = result_data.substr(0, pos);
            result_data = result_data.substr(pos + 1);
            pos = result_data.indexOf(":");
            safe_params = result_data.substr(0, pos);
            upload_params = result_data.substr(pos + 1)
        }
        if (debug_data_str != "") {
            var title = "";
            if (this.requesttype == "fileupload")
                title = "Debug Data - File: " + this.file_id;
            else if (this.requesttype == "email")
                title = "Debug Data - Email Notification";
            debug_data = {
                title: title,
                data: debug_data_str
            }
        }
        if (safe_params != "") {
            var safe_parts = safe_params.split(";");
            if (parseInt(safe_parts[2]) == 1) {
                var filedata = safe_parts[3].split(",");
                file_status = wfu_plugin_decode_string(filedata[0]);
                uploaded_file_props = filedata[4]
            }
        }
    }
    if (upload_params == "" || safe_params == "") {
        var Params = wfu_Initialize_Params();
        Params.general.shortcode_id = sid;
        Params.general.unique_id = this.unique_id;
        Params.general.state = 7;
        Params.general.files_count = this.requesttype == "fileupload" ? 1 : 0;
        Params.general.upload_finish_time = this.finish_time;
        var file_colors = WFU.fail_colors.split(",");
        var file_header = this.error_message_header;
        var file_message_type = error_code;
        if (error_code == "errorabortsuccess") {
            Params.general.fail_message = "";
            Params.general.fail_admin_message = "";
            file_colors = WFU.success_colors.split(",");
            file_header = this.success_message_header;
            file_message_type = "success"
        } else if (error_code != "errorcancel") {
            Params.general.fail_message = GlobalData.consts.message_unknown;
            Params.general.fail_admin_message = wfu_join_strings("<br />", this.error_adminmessage_unknown, this.requesttype + ":" + result_data)
        } else {
            Params.general.fail_message = GlobalData.consts.file_cancelled;
            Params.general.fail_admin_message = ""
        }
        if (Params.general.files_count > 0) {
            Params[0] = {};
            Params[0]["color"] = file_colors[0];
            Params[0]["bgcolor"] = file_colors[1];
            Params[0]["borcolor"] = file_colors[2];
            Params[0]["message_type"] = file_message_type;
            file_status = error_code;
            Params[0]["header"] = file_header;
            Params[0]["message"] = GlobalData.consts.message_timelimit;
            Params[0]["admin_messages"] = WFU.is_admin ? GlobalData.consts.message_admin_timelimit : ""
        } else
            Params.general.admin_messages.other = WFU.is_admin ? GlobalData.consts.message_admin_timelimit : "";
        if (Params.general.upload_finish_time > 0)
            if (d.getTime() < Params.general.upload_finish_time)
                if (Params.general.files_count > 0) {
                    Params[0]["message"] = Params.general.fail_message;
                    Params[0]["admin_messages"] = WFU.is_admin ? Params.general.fail_admin_message : ""
                } else
                    Params.general.admin_messages.other = WFU.is_admin ? Params.general.fail_admin_message : ""
    }
    if (upload_params == "" || safe_params == "") {
        if (WFU.debugmode)
            console.log("wfu_ProcessUploadComplete: ", sid, this.file_id, "Params obj", this.unique_id, "", [WFU.debugmode, debug_data, WFU.is_admin], this.requesttype, "");
        last = wfu_ProcessUploadComplete(sid, this.file_id, Params, this.unique_id, "", [WFU.debugmode, debug_data, WFU.is_admin], this.requesttype, "")
    } else {
        if (WFU.debugmode)
            console.log("wfu_ProcessUploadComplete: ", sid, this.file_id, "Params str", this.unique_id, safe_params, [WFU.debugmode, debug_data, WFU.is_admin], this.requesttype, js_script_enc);
        last = wfu_ProcessUploadComplete(sid, this.file_id, upload_params, this.unique_id, safe_params, [WFU.debugmode, debug_data, WFU.is_admin], this.requesttype, js_script_enc)
    }
    if (last) {
        wfu_dettach_cancel_event(sid);
        wfu_unlock_upload(sid);
        if (!!WFU.progressbar_exist)
            WFU.progressbar.hide();
        wfu_clear(sid)
    }
    if (evt.target.return_status)
        return file_status
}
function wfu_ProcessUploadComplete(sid, file_id, upload_params, unique_id, safe_output, debug_data, request_type, js_script_enc) {
    var WFU = GlobalData.WFU[sid];
    if (!sid || sid < 0)
        return;
    if (upload_params == null || upload_params == "")
        return;
    if (unique_id == "")
        return;
    if (unique_id != "no-ajax" && !GlobalData[sid])
        return;
    var do_redirect = false;
    if (typeof upload_params === "string") {
        upload_params = wfu_plugin_decode_string(upload_params.replace(/^\s+|\s+$/g, ""));
        var Params = null;
        try {
            Params = JSON.parse(upload_params)
        } catch (e) {}
        if (Params == null) {
            var safe_parts = safe_output.split(";");
            Params = wfu_Initialize_Params();
            Params.general.shortcode_id = sid;
            Params.general.unique_id = unique_id;
            Params.general.state = safe_parts[0];
            if (Params.general.state == 4)
                Params.general.state++;
            var default_colors = safe_parts[1].split(",");
            var filedata = "";
            var error_jsonparse_filemessage = GlobalData.consts.jsonparse_filemessage;
            var error_jsonparse_message = GlobalData.consts.jsonparse_message;
            var error_jsonparse_adminmessage = GlobalData.consts.jsonparse_adminmessage;
            Params.general.files_count = parseInt(safe_parts[2]);
            for (var i = 0; i < Params.general.files_count; i++) {
                Params[i] = {};
                Params[i]["color"] = default_colors[0];
                Params[i]["bgcolor"] = default_colors[1];
                Params[i]["borcolor"] = default_colors[2];
                filedata = safe_parts[i + 3].split(",");
                Params[i]["message_type"] = wfu_plugin_decode_string(filedata[0]);
                Params[i]["header"] = wfu_plugin_decode_string(filedata[1]);
                if (Params[i]["message_type"] == "success") {
                    Params[i]["header"] += error_jsonparse_filemessage;
                    Params[i]["message_type"] = "warning"
                }
                Params[i]["message"] = wfu_join_strings("<br />", error_jsonparse_message, wfu_plugin_decode_string(filedata[2]));
                Params[i]["admin_messages"] = wfu_join_strings("<br />", error_jsonparse_adminmessage, wfu_plugin_decode_string(filedata[3]))
            }
        }
    } else if (typeof upload_params === "object")
        var Params = upload_params;
    else
        return;
    if (WFU.debugmode)
        console.log("wfu_ProcessUploadComplete debug: ", debug_data);
    if (WFU.debugmode)
        console.log("wfu_ProcessUploadComplete Params: ", Params);
    var message_types = [];
    i = 0;
    while (Params[i]) {
        if (Params[i].message_type) {
            message_types.push(Params[i].message_type);
            if (Params[i].message_type.substr(0, 5) == "error")
                Params[i].message_type = Params[i].message_type.substr(0, 5)
        }
        i++
    }
    if (!GlobalData[sid])
        GlobalData[sid] = Object();
    var G = GlobalData[sid];
    if (unique_id == "no-ajax") {
        G.last = false;
        G.unique_id = "";
        G.files_count = Params.general.files_count;
        if (Params.general.state == 0)
            Params.general.files_count = 0;
        G.files_processed = Params.general.files_count;
        G.upload_state = Params.general.state;
        G.nofileupload = Params.general.state > 12 && Params.general.state < 16;
        if (!("message"in G))
            G.message = [];
        if (Params.general.message != "")
            G.message.push(Params.general.message);
        else
            G.message = [];
        G.update_wpfilebase = Params.general.update_wpfilebase;
        G.redirect_link = Params.general.redirect_link;
        G.notify_by_email = 0;
        G.admin_messages = {};
        G.admin_messages.wpfilebase = Params.general.admin_messages.wpfilebase;
        G.admin_messages.notify = Params.general.admin_messages.notify;
        G.admin_messages.redirect = Params.general.admin_messages.redirect;
        if (!("debug"in G.admin_messages))
            G.admin_messages.debug = [];
        if (debug_data[1] !== null)
            G.admin_messages.debug.push(debug_data[1]);
        if (!("other"in G.admin_messages))
            G.admin_messages.other = [];
        if (Params.general.admin_messages.other != "")
            G.admin_messages.other.push(Params.general.admin_messages.other);
        G.errors = {};
        G.errors.wpfilebase = Params.general.errors.wpfilebase;
        G.errors.notify = Params.general.errors.notify;
        G.errors.redirect = Params.general.errors.redirect;
        G.current_size = 0;
        G.total_size = 0
    } else {
        if (G.unique_id == "" || G.unique_id != unique_id || G.unique_id != Params.general.unique_id)
            return;
        if (G.last)
            return;
        if (Params.general.files_count == 0 && Params[0])
            if (Params[0].message_type == "error")
                Params.general.files_count = 1;
        var file_status = "";
        for (var i = 0; i < Params.general.files_count; i++) {
            if (Params[i].message_type == "error" && G.files_processed == 0)
                file_status = "error1";
            else if (Params[i].message_type == "error" && G.files_processed > 0)
                file_status = "error2";
            else
                file_status = Params[i].message_type;
            G.upload_state = GlobalData.filestatematch[file_status][G.upload_state]
        }
        G.files_processed += Params.general.files_count;
        if (Params.general.message != "")
            G.message.push(Params.general.message);
        if (G.update_wpfilebase == "")
            G.update_wpfilebase = Params.general.update_wpfilebase;
        if (!request_type || request_type && request_type != "email")
            G.redirect_link = Params.general.redirect_link;
        G.notify_by_email += parseInt("0" + Params.general.notify_by_email);
        if (debug_data[1] !== null)
            G.admin_messages.debug.push(debug_data[1]);
        if (Params.general.admin_messages.other != "")
            G.admin_messages.other.push(Params.general.admin_messages.other);
        if (G.admin_messages.wpfilebase == "")
            G.admin_messages.wpfilebase = Params.general.admin_messages.wpfilebase;
        if (G.admin_messages.notify == "")
            G.admin_messages.notify = Params.general.admin_messages.notify;
        if (G.admin_messages.redirect == "")
            G.admin_messages.redirect = Params.general.admin_messages.redirect;
        if (G.errors.wpfilebase == "")
            G.errors.wpfilebase = Params.general.errors.wpfilebase;
        if (G.errors.notify == "")
            G.errors.notify = Params.general.errors.notify;
        if (G.errors.redirect == "")
            G.errors.redirect = Params.general.errors.redirect
    }
    if (G.files_processed == G.files_count) {
        G.last = true;
        if (G.update_wpfilebase != "") {
            G.admin_messages.wpfilebase = "";
            wfu_notify_WPFilebase(WFU.params_index, WFU.session)
        }
        if (G.notify_by_email > 0) {
            G.admin_messages.notify = "";
            wfu_send_email_notification(sid, unique_id);
            G.last = false;
            G.notify_by_email = 0
        }
        if (G.last) {
            if (unique_id != "no-ajax" && !G.nofileupload)
                wfu_notify_server_upload_ended(sid, unique_id);
            GlobalData.UploadInProgressString = GlobalData.UploadInProgressString.replace(new RegExp("\\[" + unique_id + "\\]","g"), "")
        }
        if (G.errors.redirect != "")
            G.redirect_link = "";
        if (G.redirect_link != "" && G.last && GlobalData.UploadInProgressString.trim() == "") {
            G.upload_state = 11;
            do_redirect = true
        }
    }
    var nonadmin_message = G.message;
    var admin_message = [].concat(G.admin_messages.other, G.admin_messages.wpfilebase != "" ? [G.admin_messages.wpfilebase] : [], G.admin_messages.notify != "" ? [G.admin_messages.notify] : [], G.admin_messages.redirect != "" ? [G.admin_messages.redirect] : []);
    if (G.last)
        if (G.nofileupload) {
            if (unique_id != "no-ajax")
                if (G.upload_state == 0)
                    G.upload_state = 14;
                else if (G.upload_state < 4)
                    G.upload_state = 15;
            if (G.upload_state == 15 && Params[0]) {
                nonadmin_message.push(Params[0].message);
                admin_message.push(Params[0].admin_messages)
            }
        } else {
            if (G.files_count > 0 && G.store_nothing && G.upload_state < 3)
                G.upload_state = 19;
            if (G.files_count == 0 && G.upload_state != 12 && G.upload_state < 16)
                G.upload_state = 8;
            else if (G.upload_state < 4)
                G.upload_state += 4;
            if (G.upload_state == 4 && admin_message.length > 0)
                G.upload_state++;
            else if (G.upload_state == 5 && admin_message.length == 0 && nonadmin_message.length == 0)
                G.upload_state--
        }
    if (!!WFU.message_exist) {
        var suffix = "";
        if (G.files_count == 1 && (G.upload_state == 5 || G.upload_state == 7))
            suffix = "_singlefile";
        var final_upload_state = G.upload_state == 0 && G.nofileupload ? 13 : G.upload_state;
        var data = {
            files_count: !G.nofileupload ? G.files_count : 0,
            files_processed: !G.nofileupload ? G.files_processed : 0,
            state: final_upload_state,
            single: G.files_count == 1 && nonadmin_message.length == 0 && admin_message.length == 0 && G.last && !do_redirect && !G.nofileupload,
            color: GlobalData.States["State" + final_upload_state + suffix].color,
            bgcolor: GlobalData.States["State" + final_upload_state + suffix].bgcolor,
            borcolor: GlobalData.States["State" + final_upload_state + suffix].borcolor,
            message1: GlobalData.States["State" + final_upload_state + suffix].message,
            message2: nonadmin_message,
            message3: admin_message,
            debug_data: G.admin_messages.debug,
            files: []
        };
        for (var i = 0; i < Params.general.files_count; i++)
            data.files[i] = {
                index: i + file_id,
                result: Params[i].message_type,
                message1: Params[i].header,
                message2: Params[i].message,
                message3: Params[i].admin_messages
            };
        WFU.message.update(data)
    }
    if (js_script_enc)
        eval(wfu_plugin_decode_string(js_script_enc));
    if (do_redirect)
        wfu_Redirect(G.redirect_link);
    return G.last
}
function wfu_uploadFailed(evt, debugmode) {
    if (debugmode) {
        console.log("failure report following");
        console.log(evt)
    }
    var xhr = evt.target;
    var new_evt = {
        target: {
            responseText: "",
            shortcode_id: xhr.shortcode_id
        }
    };
    wfu_uploadComplete.call(xhr, new_evt)
}
function wfu_uploadCanceled(evt) {}
function wfu_notify_server_upload_ended(sid, unique_id) {
    var WFU = GlobalData.WFU[sid];
    var xhr = wfu_GetHttpRequestObject();
    if (xhr == null)
        return;
    var url = GlobalData.consts.ajax_url;
    params = new Array(6);
    params[0] = new Array(2);
    params[0][0] = "action";
    params[0][1] = "wfu_ajax_action";
    params[1] = new Array(2);
    params[1][0] = "wfu_uploader_nonce";
    params[1][1] = document.getElementById("wfu_uploader_nonce_" + sid).value;
    params[2] = new Array(2);
    params[2][0] = "uniqueuploadid_" + sid;
    params[2][1] = unique_id;
    params[3] = new Array(2);
    params[3][0] = "params_index";
    params[3][1] = WFU.params_index;
    params[4] = new Array(2);
    params[4][0] = "session_token";
    params[4][1] = WFU.session;
    params[5] = new Array(2);
    params[5][0] = "upload_finished";
    params[5][1] = 1;
    var parameters = "";
    for (var i = 0; i < params.length; i++)
        parameters += (i > 0 ? "&" : "") + params[i][0] + "=" + encodeURI(params[i][1]);
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4)
            if (xhr.status == 200)
                wfu_Code_Objects[sid].do_action("after_upload", xhr.responseText)
    }
    ;
    xhr.send(parameters)
}
function wfu_Initialize_Params() {
    var params = {};
    params.version = "full";
    params.general = {};
    params.general.shortcode_id = 0;
    params.general.unique_id = "";
    params.general.state = 0;
    params.general.files_count = 0;
    params.general.update_wpfilebase = "";
    params.general.redirect_link = "";
    params.general.upload_finish_time = 0;
    params.general.message = "";
    params.general.message_type = "";
    params.general.admin_messages = {};
    params.general.admin_messages.wpfilebase = "";
    params.general.admin_messages.notify = "";
    params.general.admin_messages.redirect = "";
    params.general.admin_messages.other = "";
    params.general.errors = {};
    params.general.errors.wpfilebase = "";
    params.general.errors.notify = "";
    params.general.errors.redirect = "";
    params.general.color = "";
    params.general.bgcolor = "";
    params.general.borcolor = "";
    params.general.notify_by_email = 0;
    params.general.fail_message = "";
    params.general.fail_admin_message = "";
    return params
}
function wfu_redirect_to_classic(sid, flag, adminerrorcode) {
    var WFU = GlobalData.WFU[sid];
    WFU.is_formupload = true;
    var numfiles = wfu_filesselected(sid);
    if (numfiles == 0 && !WFU.allownofile)
        return;
    if (!!WFU.subfolders_exist && numfiles > 0 && !WFU.subfolders.check())
        return;
    if (!wfu_check_required_userdata(sid, true))
        return;
    if (!wfu_Code_Objects[sid].apply_filters("pre_start_check", true))
        return;
    wfu_redirect_to_classic_cont(sid, flag, adminerrorcode)
}
function wfu_redirect_to_classic_cont(sid, flag, adminerrorcode) {
    var process_function = function(responseText) {
        var WFU = GlobalData.WFU[sid];
        var txt_value = "";
        var session_token = WFU.session;
        var success_txt = "wfu_askserver_success:";
        var error_txt = "wfu_askserver_error:";
        var pos_success = responseText.indexOf(success_txt);
        var pos_error = responseText.indexOf(error_txt);
        if (pos_success > -1) {
            txt_value = responseText.substr(pos_success + success_txt.length);
            var numfiles = wfu_filesselected(sid);
            var nofileupload = numfiles == 0 && WFU.allownofile;
            wfu_Code_Objects[sid].do_action("askserver_success", txt_value, "no-ajax");
            if (!!WFU.progressbar_exist && !nofileupload)
                WFU.progressbar.show("shuffle");
            wfu_attach_cancel_event(sid, unique_id);
            var Params = wfu_Initialize_Params();
            Params.general.shortcode_id = sid;
            Params.general.unique_id = "";
            Params.general.files_count = numfiles;
            if (nofileupload)
                Params.general.state = 13;
            wfu_ProcessUploadComplete(sid, 0, Params, "no-ajax", "", [false, null, false]);
            document.getElementById("uniqueuploadid_" + sid).value = unique_id;
            document.getElementById("nofileupload_" + sid).value = nofileupload ? "1" : "0";
            var suffix = "";
            var redirected_txt = "";
            if (flag == 1)
                redirected_txt = "_redirected";
            if (!!WFU.uploadform_exist) {
                WFU.uploadform.changeFileName("uploadedfile_" + sid + redirected_txt + suffix);
                document.getElementById("uploadedfile_" + sid + "_name").name = "uploadedfile_" + sid + redirected_txt + "_name";
                document.getElementById("uploadedfile_" + sid + "_size").name = "uploadedfile_" + sid + redirected_txt + "_size"
            }
            if (adminerrorcode > 0)
                document.getElementById("adminerrorcodes_" + sid).value = adminerrorcode;
            else
                document.getElementById("adminerrorcodes_" + sid).value = "";
            if (!!WFU.uploadform_exist) {
                WFU.uploadform.submit();
                WFU.uploadform.lock()
            }
        } else if (pos_error > -1) {
            txt_value = responseText.substr(pos_error + error_txt.length);
            wfu_unlock_upload(sid);
            wfu_Code_Objects[sid].do_action("askserver_error", txt_value)
        }
    };
    var unique_id = wfu_randomString(10);
    wfu_lock_upload(sid);
    wfu_Code_Objects[sid].do_action("pre_start");
    var pass_params = "";
    var params_obj = wfu_Code_Objects[sid].apply_filters("askserver_pass_params", {});
    for (var prop in params_obj)
        if (params_obj.hasOwnProperty(prop))
            pass_params += "&" + prop + "=" + params_obj[prop];
    var d = new Date;
    var url = GlobalData.consts.ajax_url + "?action=wfu_ajax_action_ask_server&wfu_uploader_nonce=" + document.getElementById("wfu_uploader_nonce_" + sid).value + "&sid=" + sid + "&unique_id=" + unique_id + "&start_time=" + d.getTime() + "&session_token=" + GlobalData.WFU[sid].session + pass_params;
    var xmlhttp = wfu_GetHttpRequestObject();
    if (xmlhttp == null) {
        var i = document.createElement("iframe");
        if (i) {
            i.style.display = "none";
            i.src = url;
            document.body.appendChild(i);
            i.onload = function() {
                process_function(i.contentDocument.body.innerHTML)
            }
            ;
            return
        } else {
            wfu_Code_Objects[sid].do_action("not_supported");
            return
        }
    }
    xmlhttp.open("GET", url, true);
    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4)
            if (xmlhttp.status == 200)
                process_function(xmlhttp.responseText);
            else {
                alert(GlobalData.consts.remoteserver_noresult);
                wfu_Code_Objects[sid].do_action("askserver_noresult")
            }
    }
    ;
    xmlhttp.send(null)
}
Code_Initializators[Code_Initializators.length] = function(sid) {
    var CBUV_Code_Objects = {};
    CBUV_Code_Objects.pre_start_check = function(attr) {
        if (!attr)
            return attr;
        var sid = this.sid;
        var result = true;
        if (!!GlobalData.WFU[sid].consent_exist) {
            if (GlobalData.WFU[sid].consent.consent_format != "prompt" && document.getElementById("consentresult_" + sid).value == "") {
                alert(GlobalData.consts.wfu_consent_notcompleted);
                result = false
            } else if (GlobalData.WFU[sid].consent.consent_format == "prompt") {
                document.getElementById("consentresult_" + sid).value = confirm(GlobalData.WFU[sid].consent.consent_question) ? "yes" : "no";
                result = true
            }
            if (GlobalData.WFU[sid].consent.no_rejects_upload && document.getElementById("consentresult_" + sid).value == "no") {
                alert(GlobalData.WFU[sid].consent_rejection_message);
                result = false
            }
        }
        return result
    }
    ;
    CBUV_Code_Objects.pre_start_ask_server = function(attr, has_filters) {
        if (attr)
            return attr;
        var sid = this.sid;
        var consent_ask_server = GlobalData.WFU[sid].consent_maybe_ask_server && !GlobalData.WFU[sid].consent_exist;
        return has_filters == "true" || consent_ask_server
    }
    ;
    CBUV_Code_Objects.askserver_pass_params = function(params) {
        var sid = this.sid;
        var farr = wfu_get_filelist(sid);
        var filenames = "";
        var filesizes = "";
        for (var i = 0; i < farr.length; i++) {
            if (i > 0) {
                filenames += ";";
                filesizes += ";"
            }
            filenames += wfu_plugin_encode_string(farr[i].name);
            filesizes += farr[i].size
        }
        params.filenames = filenames;
        params.filesizes = filesizes;
        if (GlobalData.WFU[sid].consent_maybe_ask_server && !GlobalData.WFU[sid].consent_exist) {
            params.consent_check = "1";
            params.consent_rejection_message = GlobalData.WFU[sid].consent_rejection_message
        }
        return params
    }
    ;
    CBUV_Code_Objects.askserver_success = function(response, mode) {
        var sid = this.sid;
        var upload_status = "success";
        var txt_match = response.match(/CBUVJS\[(.*?)\]/);
        var txt_header = txt_match ? typeof txt_match[1] != "undefined" ? txt_match[1] : "" : "";
        if (txt_header != "")
            eval(wfu_plugin_decode_string(txt_header))
    }
    ;
    CBUV_Code_Objects.askserver_error = function(response, mode) {
        var sid = this.sid;
        var upload_status = "error";
        var txt_match = response.match(/CBUVJS\[(.*?)\]/);
        var txt_header = txt_match ? typeof txt_match[1] != "undefined" ? txt_match[1] : "" : "";
        if (txt_header != "")
            eval(wfu_plugin_decode_string(txt_header));
        txt_match = response.match(/CBUV\[(.*?)\]/);
        txt_header = txt_match ? typeof txt_match[1] != "undefined" ? txt_match[1] : "" : "";
        if (txt_header != "") {
            var Params = wfu_Initialize_Params();
            GlobalData[sid] = {};
            Params.general.shortcode_id = sid;
            Params.general.message = txt_header;
            Params.general.state = 12;
            wfu_ProcessUploadComplete(sid, 0, Params, "no-ajax", "", [false, null, false]);
            wfu_clear(sid)
        }
    }
    ;
    CBUV_Code_Objects.lock_upload = function() {
        var sid = this.sid;
        if (!!GlobalData.WFU[sid].consent_exist)
            GlobalData.WFU[sid].consent.update("lock")
    }
    ;
    CBUV_Code_Objects.unlock_upload = function() {
        var sid = this.sid;
        if (!!GlobalData.WFU[sid].consent_exist)
            GlobalData.WFU[sid].consent.update("unlock")
    }
    ;
    CBUV_Code_Objects.clear_upload = function() {
        var sid = this.sid;
        var WFU = GlobalData.WFU[sid];
        if (!!WFU.consent_exist)
            if (WFU.consent.remember_consent) {
                WFU.consent.update("clear");
                WFU.consent_exist = false
            } else
                WFU.consent.update("init")
    }
    ;
    CBUV_Code_Objects.upload_pass_params = function(params, mode) {
        var sid = this.sid;
        if (!!GlobalData.WFU[sid].consent_exist)
            params.consent_result = document.getElementById("consentresult_" + sid).value;
        return params
    }
    ;
    CBUV_Code_Objects.after_upload = function(response) {
        var sid = this.sid;
        var txt_match = response.match(/CBUVJS\[(.*?)\]/);
        var txt_header = txt_match ? typeof txt_match[1] != "undefined" ? txt_match[1] : "" : "";
        if (txt_header != "")
            eval(wfu_plugin_decode_string(txt_header))
    }
    ;
    return CBUV_Code_Objects
}
;
function wfu_filesselected(sid) {
    var WFU = GlobalData.WFU[sid];
    var farr = wfu_get_filelist(sid);
    if (farr.length == 0 && !WFU.allownofile && !!WFU.textbox_exist)
        WFU.textbox.update("nofile");
    return farr.length
}
function wfu_check_required_userdata(sid, prompt) {
    var WFU = GlobalData.WFU[sid];
    var userdata_count = wfu_get_userdata_count(sid);
    var req_empty = false;
    for (var i = 0; i < userdata_count; i++) {
        WFU.userdata.props[i].store();
        var error_message = "";
        if (WFU.userdata.props[i].required)
            error_message = WFU.userdata.codes[i].empty();
        if (error_message === "" && WFU.userdata.codes[i].validate != null && WFU.userdata.props[i].validate)
            error_message = WFU.userdata.codes[i].validate();
        if (error_message !== "") {
            if (prompt)
                WFU.userdata.prompt(WFU.userdata.props[i], error_message);
            req_empty = true
        }
    }
    return !req_empty
}
function wfu_HTML5UploadFile(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!wfu_BrowserCaps.supportsAJAX) {
        wfu_redirect_to_classic(sid, 1, 1);
        return
    }
    if (!wfu_BrowserCaps.supportsHTML5) {
        wfu_redirect_to_classic(sid, 1, 2);
        return
    }
    var xhr = wfu_GetHttpRequestObject();
    if (xhr == null)
        return;
    var numfiles = wfu_filesselected(sid);
    if (numfiles == 0 && !WFU.allownofile)
        return;
    if (numfiles == 0)
        wfu_selectbutton_clicked(sid);
    if (!!WFU.subfolders_exist && numfiles > 0 && !WFU.subfolders.check()) {
        if (WFU.singlebutton)
            wfu_clear_files(sid);
        return
    }
    var numpasses = numfiles;
    numpasses += numpasses;
    if (!wfu_check_required_userdata(sid, true)) {
        if (WFU.singlebutton)
            wfu_clear_files(sid);
        return
    }
    if (!wfu_Code_Objects[sid].apply_filters("pre_start_check", true))
        return;
    var unique_upload_id = wfu_randomString(10);
    wfu_lock_upload(sid);
    wfu_Code_Objects[sid].do_action("pre_start");
    if (!wfu_Code_Objects[sid].apply_filters("pre_start_ask_server", false, WFU.has_filters ? "true" : "false"))
        wfu_HTML5UploadFile_cont(sid, unique_upload_id);
    else {
        var url = GlobalData.consts.ajax_url;
        params = new Array(5);
        params[0] = new Array(2);
        params[0][0] = "action";
        params[0][1] = "wfu_ajax_action_ask_server";
        params[1] = new Array(2);
        params[1][0] = "session_token";
        params[1][1] = WFU.session;
        params[2] = new Array(2);
        params[2][0] = "sid";
        params[2][1] = sid;
        params[3] = new Array(2);
        params[3][0] = "unique_id";
        params[3][1] = unique_upload_id;
        params[4] = new Array(2);
        params[4][0] = "wfu_uploader_nonce";
        params[4][1] = document.getElementById("wfu_uploader_nonce_" + sid).value;
        var params_obj = wfu_Code_Objects[sid].apply_filters("askserver_pass_params", {});
        for (var prop in params_obj)
            if (params_obj.hasOwnProperty(prop))
                params.push([prop, params_obj[prop]]);
        var parameters = "";
        for (var i = 0; i < params.length; i++)
            parameters += (i > 0 ? "&" : "") + params[i][0] + "=" + encodeURI(params[i][1]);
        xhr.open("POST", url, true);
        xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhr.onreadystatechange = function() {
            if (xhr.readyState == 4)
                if (xhr.status == 200) {
                    var txt = xhr.responseText;
                    var txt_value = "";
                    var success_txt = "wfu_askserver_success:";
                    var error_txt = "wfu_askserver_error:";
                    var pos_success = txt.indexOf(success_txt);
                    var pos_error = txt.indexOf(error_txt);
                    var pos = -1;
                    if (pos_success > -1) {
                        txt_value = txt.substr(pos_success + success_txt.length);
                        wfu_Code_Objects[sid].do_action("askserver_success", txt_value, "ajax");
                        wfu_HTML5UploadFile_cont(sid, unique_upload_id)
                    } else if (pos_error > -1) {
                        txt_value = txt.substr(pos_error + error_txt.length);
                        wfu_unlock_upload(sid);
                        wfu_Code_Objects[sid].do_action("askserver_error", txt_value)
                    }
                } else {
                    alert(GlobalData.consts.remoteserver_noresult);
                    wfu_unlock_upload(sid);
                    wfu_Code_Objects[sid].do_action("askserver_noresult")
                }
        }
        ;
        xhr.send(parameters)
    }
}
function wfu_HTML5UploadFile_cont(sid, unique_upload_id) {
    function sendfile(ind, file, only_check, force_close_connection) {
        ret_status = true;
        var xhr = wfu_GetHttpRequestObject();
        var xhr_close_connection = wfu_GetHttpRequestObject();
        if (xhr == null || xhr_close_connection == null)
            return;
        var fd = null;
        var fd_close_connection = null;
        try {
            var fd = new FormData;
            var fd_close_connection = new FormData
        } catch (e) {}
        if (fd == null || fd_close_connection == null)
            return;
        fd.append("action", "wfu_ajax_action");
        fd.append("wfu_uploader_nonce", document.getElementById("wfu_uploader_nonce_" + sid).value);
        if (!only_check)
            fd.append("uploadedfile_" + sid + suffice, file);
        fd.append("uploadedfile_" + sid + "_index", ind);
        fd.append("uploadedfile_" + sid + "_name", wfu_plugin_encode_string(farr[ind].name));
        fd.append("uploadedfile_" + sid + "_size", farr[ind].size);
        fd.append("uniqueuploadid_" + sid, unique_upload_id);
        fd.append("params_index", WFU.params_index);
        fd.append("subdir_sel_index", subdir_sel_index);
        fd.append("nofileupload_" + sid, nofileupload ? "1" : "0");
        if (only_check)
            fd.append("only_check", "1");
        else
            fd.append("only_check", "0");
        fd.append("session_token", WFU.session);
        var other_params = wfu_Code_Objects[sid].apply_filters("upload_pass_params", {}, "ajax");
        for (var prop in other_params)
            if (other_params.hasOwnProperty(prop))
                fd.append(prop, other_params[prop]);
        var userdata_count = wfu_get_userdata_count(sid);
        for (var ii = 0; ii < userdata_count; ii++)
            fd.append("hiddeninput_" + sid + "_userdata_" + ii, document.getElementById("hiddeninput_" + sid + "_userdata_" + ii).value);
        wfu_initialize_fileupload_xhr(xhr, sid, unique_upload_id, ind, farr[ind].name);
        xhr.loading = true;
        if (!only_check) {
            xhr.size = file.size;
            xhr.totalsize = farr[ind].size
        }
        if (force_close_connection) {
            fd_close_connection.append("action", "wfu_ajax_action");
            fd_close_connection.append("wfu_uploader_nonce", document.getElementById("wfu_uploader_nonce_" + sid).value);
            fd_close_connection.append("params_index", WFU.params_index);
            fd_close_connection.append("session_token", WFU.session);
            fd_close_connection.append("force_connection_close", "1");
            xhr_close_connection.open("POST", GlobalData.consts.ajax_url, false);
            try {
                xhr_close_connection.send(fd_close_connection)
            } catch (err) {}
            ret_status = xhr_close_connection.responseText.indexOf("success") > -1
        }
        if (ret_status)
            if (!only_check) {
                xhr.upload.xhr = xhr;
                xhr.upload.dummy = 1;
                xhr.upload.addEventListener("loadstart", wfu_loadStart, false);
                xhr.upload.addEventListener("progress", new Function("evt","wfu_uploadProgress(evt, " + sid + ", " + xhr.xhrid + ", " + (WFU.debugmode ? "true" : "false") + ");"), false);
                xhr.addEventListener("load", wfu_uploadComplete, false);
                xhr.addEventListener("error", new Function("evt","wfu_uploadFailed(evt, " + (WFU.debugmode ? "true" : "false") + ");"), false);
                xhr.addEventListener("abort", wfu_uploadCanceled, false);
                xhr.open("POST", GlobalData.consts.ajax_url, true);
                xhr.send(fd)
            } else {
                xhr.addEventListener("load", function(evt) {
                    evt = {
                        target: {
                            responseText: evt.target.responseText,
                            shortcode_id: sid,
                            return_status: true
                        }
                    };
                    var file_status = wfu_uploadComplete.call(xhr, evt);
                    xhr.file_id = 0;
                    ret_status = file_status == "success" || file_status == "warning";
                    if (ret_status && !nofileupload)
                        sendfile(ind, file, false, false);
                    else if (ret_status && nofileupload)
                        ;
                }, false);
                xhr.addEventListener("error", function(evt) {
                    return
                }, false);
                xhr.open("POST", GlobalData.consts.ajax_url, true);
                xhr.send(fd)
            }
        else {
            var evt = {
                target: {
                    responseText: "",
                    shortcode_id: sid
                }
            };
            wfu_uploadComplete.call(xhr, evt)
        }
        inc++;
        return ret_status
    }
    var WFU = GlobalData.WFU[sid];
    var subdir_sel_index = -1;
    if (!!WFU.subfolders_exist)
        subdir_sel_index = WFU.subfolders.index();
    var farr = wfu_get_filelist(sid);
    var nofileupload = false;
    if (farr.length == 0 && WFU.allownofile) {
        nofileupload = true;
        farr = [{
            name: "dummy.txt",
            size: 0
        }]
    }
    var suffice = "";
    GlobalData.UploadInProgressString += "[" + unique_upload_id + "]";
    GlobalData[sid] = {};
    GlobalData[sid].unique_id = unique_upload_id;
    GlobalData[sid].last = false;
    GlobalData[sid].files_count = 1;
    GlobalData[sid].files_processed = 0;
    GlobalData[sid].upload_state = 0;
    GlobalData[sid].nofileupload = nofileupload;
    GlobalData[sid].store_nothing = !!WFU.consent_exist && document.getElementById("consentresult_" + sid).value == "no" && WFU.not_store_files;
    GlobalData[sid].message = [];
    GlobalData[sid].update_wpfilebase = "";
    GlobalData[sid].redirect_link = "";
    GlobalData[sid].notify_by_email = 0;
    GlobalData[sid].admin_messages = {};
    GlobalData[sid].admin_messages.wpfilebase = "";
    GlobalData[sid].admin_messages.notify = "";
    GlobalData[sid].admin_messages.redirect = "";
    GlobalData[sid].admin_messages.debug = [];
    GlobalData[sid].admin_messages.other = [];
    GlobalData[sid].errors = {};
    GlobalData[sid].errors.wpfilebase = "";
    GlobalData[sid].errors.notify = "";
    GlobalData[sid].errors.redirect = "";
    GlobalData[sid].xhrs = Array();
    GlobalData[sid].metricstotal = {
        size: farr[0].size,
        loaded: 0,
        progress_pos: 0
    };
    GlobalData[sid].metrics = [{
        size: farr[0].size,
        loaded: 0,
        progress_pos: 0
    }];
    if (!!WFU.progressbar_exist && !nofileupload)
        WFU.progressbar.show("progressive");
    wfu_attach_cancel_event(sid, unique_upload_id);
    var Params = wfu_Initialize_Params();
    Params.general.shortcode_id = sid;
    Params.general.unique_id = unique_upload_id;
    wfu_ProcessUploadComplete(sid, 0, Params, unique_upload_id, "", [false, null, false]);
    var inc = 0;
    var ret_status = true;
    var i = 0;
    var fprops = [];
    sendfile(i, farr[i], true, false)
}
function wfu_initialize_fileupload_xhr(xhr, sid, unique_upload_id, file_ind, filename) {
    var WFU = GlobalData.WFU[sid];
    var xhrid = file_ind >= 0 ? GlobalData[sid].xhrs.push(xhr) - 1 : -1;
    var d = new Date;
    xhr.xhrid = xhrid;
    xhr.shortcode_id = sid;
    xhr.requesttype = file_ind >= 0 ? "fileupload" : "email";
    xhr.file_id = file_ind + 1;
    xhr.size = 0;
    xhr.totalsize = 0;
    xhr.loading = false;
    xhr.deltasize = 0;
    xhr.deltaloaded = 0;
    xhr.sizeloaded = 0;
    xhr.aborted = false;
    xhr.unique_id = unique_upload_id;
    xhr.start_time = d.getTime();
    xhr.end_time = xhr.start_time;
    xhr.finish_time = xhr.start_time + parseInt(GlobalData.consts.max_time_limit) * 1E3;
    xhr.success_message_header = WFU.success_header.replace(/%username%/g, "no data");
    xhr.success_message_header = xhr.success_message_header.replace(/%useremail%/g, "no data");
    xhr.success_message_header = xhr.success_message_header.replace(/%filename%/g, filename);
    xhr.success_message_header = xhr.success_message_header.replace(/%filepath%/g, filename);
    xhr.error_message_header = WFU.error_header.replace(/%username%/g, "no data");
    xhr.error_message_header = xhr.error_message_header.replace(/%useremail%/g, "no data");
    xhr.error_message_header = xhr.error_message_header.replace(/%filename%/g, filename);
    xhr.error_message_header = xhr.error_message_header.replace(/%filepath%/g, filename);
    xhr.error_message_failed = GlobalData.consts.message_failed;
    xhr.error_message_cancelled = GlobalData.consts.message_cancelled;
    xhr.error_adminmessage_unknown = GlobalData.consts.adminmessage_unknown.replace(/%username%/g, "no data");
    xhr.error_adminmessage_unknown = xhr.error_adminmessage_unknown.replace(/%useremail%/g, "no data");
    xhr.error_adminmessage_unknown = xhr.error_adminmessage_unknown.replace(/%filename%/g, filename);
    xhr.error_adminmessage_unknown = xhr.error_adminmessage_unknown.replace(/%filepath%/g, filename)
}
function wfu_get_userdata_count(sid) {
    var WFU = GlobalData.WFU[sid];
    var fields_count = 0;
    if (!!WFU.userdata_exist)
        fields_count = WFU.userdata.props.length;
    return fields_count
}
function wfu_lock_upload(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.textbox_exist)
        WFU.textbox.update("lock");
    if (!!WFU.uploadform_exist)
        WFU.uploadform.lock();
    if (!!WFU.subfolders_exist)
        WFU.subfolders.toggle(false);
    if (!!WFU.submit_exist)
        WFU.submit.toggle(false);
    var userdata_count = wfu_get_userdata_count(sid);
    for (var i = 0; i < userdata_count; i++)
        WFU.userdata.codes[i].lock();
    wfu_Code_Objects[sid].do_action("lock_upload")
}
function wfu_unlock_upload(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.textbox_exist)
        WFU.textbox.update("unlock");
    if (!!WFU.uploadform_exist)
        WFU.uploadform.unlock();
    if (!!WFU.subfolders_exist)
        WFU.subfolders.toggle(true);
    if (!!WFU.submit_exist)
        WFU.submit.toggle(true);
    var userdata_count = wfu_get_userdata_count(sid);
    for (var i = 0; i < userdata_count; i++)
        WFU.userdata.codes[i].unlock();
    wfu_Code_Objects[sid].do_action("unlock_upload")
}
function wfu_clear_files(sid) {
    var WFU = GlobalData.WFU[sid];
    if (!!WFU.uploadform_exist)
        WFU.uploadform.reset();
    if (typeof WFU.filearray != "undefined") {
        WFU.filearray.length = 0;
        WFU.filearrayprops.length = 0
    }
    if (!!WFU.textbox_exist)
        WFU.textbox.update("clear")
}
function wfu_check_reset(sid) {
    var WFU = GlobalData.WFU[sid];
    var G = GlobalData[sid];
    if (WFU.resetmode == "always")
        return true;
    else if (WFU.resetmode == "never")
        return false;
    else if (WFU.resetmode == "onsuccess")
        return [4, 5, 6, 14].indexOf(G.upload_state) > -1;
    else if (WFU.resetmode == "onfullsuccess")
        return [4, 5, 14].indexOf(G.upload_state) > -1;
    else
        return true
}
function wfu_clear(sid) {
    var WFU = GlobalData.WFU[sid];
    var do_reset = wfu_check_reset(sid);
    wfu_clear_files(sid);
    if (do_reset) {
        if (!!WFU.subfolders_exist)
            WFU.subfolders.reset();
        var userdata_count = wfu_get_userdata_count(sid);
        for (var i = 0; i < userdata_count; i++)
            WFU.userdata.codes[i].reset();
        if (!!WFU.uploadform_exist)
            WFU.uploadform.resetDummy()
    }
    wfu_Code_Objects[sid].do_action("clear_upload")
}
function wfu_invoke_shortcode_editor(WFU) {
    var sid = WFU.shortcode_id;
    var same = 0;
    var n = GlobalData.WFU.n;
    if (WFU.shortcode_tag == "wordpress_file_upload_browser")
        n = GlobalData.WFUB.n;
    for (var i = 0; i < n.length; i++)
        if (n[i] == sid)
            same++;
    if (same == 0)
        return;
    if (same > 1) {
        alert(GlobalData.consts.same_pluginid);
        return
    }
    var xhr = wfu_GetHttpRequestObject();
    if (xhr == null)
        return;
    WFU.visualeditorbutton.update("on_invoke");
    var url = GlobalData.consts.ajax_url;
    params = new Array(6);
    params[0] = new Array(2);
    params[0][0] = "action";
    params[0][1] = "wfu_ajax_action_edit_shortcode";
    params[1] = new Array(2);
    params[1][0] = "upload_id";
    params[1][1] = sid;
    params[2] = new Array(2);
    params[2][0] = "post_id";
    params[2][1] = WFU.post_id;
    params[3] = new Array(2);
    params[3][0] = "post_hash";
    params[3][1] = WFU.post_hash;
    params[4] = new Array(2);
    params[4][0] = "shortcode_tag";
    params[4][1] = WFU.shortcode_tag;
    params[5] = new Array(2);
    params[5][0] = "widget_id";
    params[5][1] = WFU.widgetid ? WFU.widgetid : "";
    var parameters = "";
    for (var i = 0; i < params.length; i++)
        parameters += (i > 0 ? "&" : "") + params[i][0] + "=" + encodeURI(params[i][1]);
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4)
            if (xhr.status == 200) {
                WFU.visualeditorbutton.update("on_open");
                var start_text = "wfu_edit_shortcode:";
                var pos = xhr.responseText.indexOf(start_text);
                if (pos == -1)
                    pos = xhr.responseText.length;
                var messages = xhr.responseText.substr(0, pos);
                var response = xhr.responseText.substr(pos + start_text.length, xhr.responseText.length - pos - start_text.length);
                pos = response.indexOf(":");
                var txt_header = response.substr(0, pos);
                txt_value = response.substr(pos + 1, response.length - pos - 1);
                if (txt_header == "success") {
                    var editor_window = window.open(wfu_plugin_decode_string(txt_value), "_blank");
                    if (editor_window)
                        editor_window.plugin_window = window;
                    else
                        alert(GlobalData.consts.enable_popups)
                } else if (txt_header == "check_page_obsolete")
                    alert(txt_value)
            }
    }
    ;
    xhr.send(parameters)
}
wfu_initialize_webcam = function(sid, mode, audiocapture, videowidth, videoheight, videoaspectratio, videoframerate, camerafacing, maxrecordtime) {
    if (typeof wfu_parse_video_width == "undefined")
        wfu_parse_video_width = function(videowidth) {
            var vw = parseInt(videowidth);
            if (vw > 0) {
                this.empty = false;
                this.video.width = vw
            }
        }
        ;
    if (typeof wfu_parse_video_height == "undefined")
        wfu_parse_video_height = function(videoheight) {
            var vh = parseInt(videoheight);
            if (vh > 0) {
                this.empty = false;
                this.video.height = vh
            }
        }
        ;
    if (typeof wfu_parse_video_aspectratio == "undefined")
        wfu_parse_video_aspectratio = function(videoaspectratio) {
            var ar = parseFloat(videoaspectratio);
            if (ar > 0) {
                this.empty = false;
                this.video.aspectRatio = ar
            }
        }
        ;
    if (typeof wfu_parse_video_framerate == "undefined")
        wfu_parse_video_framerate = function(videoframerate) {
            var fr = parseFloat(videoframerate);
            if (fr > 0) {
                this.empty = false;
                this.video.frameRate = fr
            }
        }
        ;
    if (typeof wfu_parse_video_facingmode == "undefined")
        wfu_parse_video_facingmode = function(camerafacing) {
            var cf = camerafacing == "front" ? "user" : camerafacing == "back" ? "environment" : "";
            if (cf != "") {
                this.empty = false;
                this.video.facingMode = cf
            }
        }
        ;
    var video_settings = {
        empty: true,
        video: {}
    };
    wfu_parse_video_width.call(video_settings, videowidth);
    wfu_parse_video_height.call(video_settings, videoheight);
    wfu_parse_video_aspectratio.call(video_settings, videoaspectratio);
    wfu_parse_video_framerate.call(video_settings, videoframerate);
    wfu_parse_video_facingmode.call(video_settings, camerafacing);
    var WebcamProps = {
        mode: mode,
        audio: audiocapture == "true",
        video: video_settings.empty ? true : video_settings.video,
        maxrecordtime: maxrecordtime
    };
    GlobalData.WFU[sid].webcamProps = WebcamProps;
    wfu_reinitialize_webcam(sid)
}
;
wfu_reinitialize_webcam = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    webcam_props.active = true;
    webcam_props.width = 0;
    webcam_props.width = 0;
    webcam_props.timeStart = 0;
    webcam_props.duration = 0;
    webcam_props.counting = false;
    webcam_props.stream = null;
    webcam_props.media = null;
    webcam_props.blobs = null;
    webcam_props.playing = false;
    var WebcamProps = webcam_props;
    webcam_obj.updateStatus("idle");
    var constraints = {
        audio: WebcamProps.audio,
        video: WebcamProps.video
    };
    if (typeof Promise == "undefined") {
        Promise = function(mainCallback) {
            this.mainCallback = mainCallback;
            this.then = function(successCallback) {
                this.successCallback = successCallback;
                return this
            }
            ;
            this["catch"] = function(errorCallback) {
                mainCallback(this.successCallback, errorCallback)
            }
        }
        ;
        PromiseRejected = function(error) {
            this.then = function(successCallback) {
                return this
            }
            ;
            this["catch"] = function(errorCallback) {
                errorCallback(error)
            }
        }
        ;
        Promise.reject = function(error) {
            return new PromiseRejected(error)
        }
    }
    var promisifiedOldGUM = function(constraints, successCallback, errorCallback) {
        var getUserMedia = navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia || navigator.msGetUserMedia;
        if (!getUserMedia || typeof MediaRecorder == "undefined")
            return Promise.reject(new Error("getUserMedia is not implemented in this browser"));
        return new Promise(function(successCallback, errorCallback) {
            getUserMedia.call(navigator, constraints, successCallback, errorCallback)
        }
        )
    };
    if (navigator.mediaDevices === undefined)
        navigator.mediaDevices = {};
    if (navigator.mediaDevices.getUserMedia === undefined)
        navigator.mediaDevices.getUserMedia = promisifiedOldGUM;
    navigator.mediaDevices.getUserMedia(constraints).then(function(stream) {
        webcam_props.stream = stream;
        webcam_obj.setVideoProperties({
            autoplay: true,
            ontimeupdate: null,
            onerror: null,
            onloadeddata: function(e) {
                wfu_webcam_init_callback(sid)
            },
            srcObject: stream
        });
        webcam_obj.initButtons(WebcamProps.mode)
    })["catch"](function(e) {
        console.log("Video not supported!", e);
        webcam_obj.updateStatus("video_notsupported")
    })
}
;
wfu_webcam_init_callback = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    var video_size = webcam_obj.videoSize();
    webcam_props.width = video_size.width;
    webcam_props.height = video_size.height;
    webcam_obj.initCallback()
}
;
wfu_webcam_counter_status = function(sid, action) {
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (action == "start") {
        var d = new Date;
        webcam_props.duration = 0;
        webcam_props.timeStart = d.getTime() / 1E3;
        webcam_props.counting = true;
        wfu_webcam_update_counter(sid)
    } else {
        var d = new Date;
        webcam_props.duration = d.getTime() / 1E3 - webcam_props.timeStart;
        webcam_props.counting = false
    }
}
;
wfu_webcam_update_counter = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.counting) {
        var d = new Date;
        var dif = d.getTime() / 1E3 - webcam_props.timeStart;
        webcam_obj.updateTimer(dif);
        setTimeout(function() {
            wfu_webcam_update_counter(sid)
        }, 100)
    }
}
;
wfu_webcam_onoff = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.active) {
        webcam_obj.updateStatus("off");
        webcam_obj.updateButtonStatus("hidden");
        if (webcam_props.stream && webcam_props.stream.stop)
            webcam_props.stream.stop();
        webcam_props.stream = null;
        webcam_props.media = null;
        webcam_props.blobs = null;
        webcam_props.active = false
    } else
        wfu_reinitialize_webcam(sid);
    wfu_selectbutton_clicked(sid)
}
;
wfu_webcam_golive = function(sid) {
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.playing)
        return;
    wfu_reinitialize_webcam(sid);
    wfu_add_files(sid, [], false);
    wfu_selectbutton_clicked(sid);
    wfu_update_uploadbutton_status(sid)
}
;
wfu_webcam_start_rec = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.media && webcam_props.media.state && webcam_props.media.state == "recording")
        return;
    try {
        webcam_props.media = new MediaRecorder(webcam_props.stream)
    } catch (err) {
        alert(GlobalData.consts.webcam_video_notsupported);
        return
    }
    webcam_props.blobs = [];
    webcam_props.media.ondataavailable = function(e) {
        var d = new Date;
        var dif = d.getTime() / 1E3 - webcam_props.timeStart;
        if (webcam_props.maxrecordtime == -1 || webcam_props.maxrecordtime > 0 && dif <= webcam_props.maxrecordtime) {
            if (e.data && e.data.size > 0)
                webcam_props.blobs.push(e.data)
        } else
            wfu_webcam_stop_rec(sid)
    }
    ;
    webcam_obj.updateButtonStatus("recording");
    wfu_webcam_counter_status(sid, "start");
    webcam_props.media.onstop = function(e) {
        wfu_webcam_counter_status(sid, "stop");
        webcam_obj.updateButtonStatus("after_recording");
        wfu_webcam_onstop(e, sid)
    }
    ;
    webcam_props.media.start(10)
}
;
wfu_webcam_stop_rec = function(sid) {
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    webcam_props.media.stop()
}
;
wfu_webcam_onstop = function(e, sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.blobs.length == 0) {
        alert(GlobalData.consts.webcam_video_nothingrecorded);
        wfu_webcam_golive(sid)
    } else {
        if (webcam_props.stream)
            webcam_obj.screenshot();
        var superBuffer = new Blob(webcam_props.blobs,{
            type: "video/mp4"
        });
        webcam_obj.setVideoProperties({
            autoplay: false,
            ontimeupdate: function(e) {
                wfu_webcam_update_pos(sid)
            },
            onended: function(e) {
                wfu_webcam_ended(sid)
            },
            onloadeddata: function(e) {
                if (webcam_obj.readyState() >= 2)
                    webcam_obj.updateButtonStatus("ready_playback")
            },
            onerror: function(e) {
                webcam_obj.setVideoProperties({
                    onloadeddata: null,
                    srcObject: webcam_props.stream
                })
            },
            srcObject: superBuffer
        });
        superBuffer.name = "video.mp4";
        wfu_add_files(sid, [{
            file: superBuffer,
            props: {}
        }], false);
        wfu_update_uploadbutton_status(sid)
    }
}
;
wfu_webcam_play = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.playing)
        return;
    webcam_obj.updateButtonStatus("playing");
    webcam_props.playing = true;
    webcam_obj.play()
}
;
wfu_webcam_ended = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    webcam_obj.ended();
    webcam_obj.updateButtonStatus("ready_playback");
    webcam_props.playing = false
}
;
wfu_webcam_pause = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    webcam_obj.pause();
    webcam_obj.updateButtonStatus("ready_playback");
    webcam_props.playing = false
}
;
wfu_webcam_back = function(sid) {
    GlobalData.WFU[sid].webcam.back()
}
;
wfu_webcam_fwd = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    webcam_obj.fwd(webcam_props.duration)
}
;
wfu_webcam_take_picture = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    if (webcam_props.stream) {
        webcam_obj.screenshot(function(image_file) {
            image_file.name = "image.png";
            wfu_add_files(sid, [{
                file: image_file,
                props: {}
            }], false);
            wfu_update_uploadbutton_status(sid)
        }, "image/png");
        webcam_obj.updateButtonStatus("after_screenshot")
    }
}
;
wfu_webcam_update_pos = function(sid) {
    var webcam_obj = GlobalData.WFU[sid].webcam;
    var webcam_props = GlobalData.WFU[sid].webcamProps;
    webcam_obj.updatePlayProgress(webcam_props.duration);
    webcam_obj.updateTimer(video.currentTime)
}
;
wfu_run_js_from_bank();
