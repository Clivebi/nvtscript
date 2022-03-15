func os_get_best_cpe(  ){
	var best_os_cpe;
	best_os_cpe = get_kb_item( "HostDetails/OS/BestMatchCPE" );
	if(best_os_cpe){
		return best_os_cpe;
	}
	return NULL;
}
func os_get_best_txt(  ){
	var best_os_txt;
	best_os_txt = get_kb_item( "HostDetails/OS/BestMatchTXT" );
	if(best_os_txt){
		return best_os_txt;
	}
	return NULL;
}
func os_host_runs( ospattern ){
	var best_os;
	if(!ospattern){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#os_host_runs" );
	}
	best_os = os_get_best_cpe();
	if(isnull( best_os )){
		best_os = os_get_best_txt();
		if(isnull( best_os )){
			return "unknown";
		}
	}
	if(ContainsString( tolower( ospattern ), "linux" )){
		ospattern = "(" + ospattern + "|apc:aos|ubuntu|debian|bsd|opensuse|fedora|suse|red ?hat|centos|mandriva|mandrake|mageia|slackware|conectiva|amazon|oracle|d-link(:| )d|euleros|openeuler|" + "turbolinux|gentoo|cisco|apple|fortios|junos|screenos|univention|esx|xen|pan-?os|qnap|synology|greenbone|hyperip|simatic|rugged(_| )operating(_| )system|vibnode|avm(:| )fritz|(my|wd)(_| )cloud|" + "intelbras(:| )ncloud|ricoh:iwb|nucleus(_| )rtos|vxworks|chip-rtos|simatic(_| )hmi|ibm(:| )os(/|_)400|novell|rockwell ?automation(:| )(micrologix|powermonitor)|beward|" + "tippingpoint(_| )operating(_| )system|data(_| )ontap|(zavio|tp-link|pearl|qsee)(:| )ip(_| )camera|riverbed(_| )optimization(_| )system|synetica(:| )datastream|" + "ricoh(:| ).+_firmware|lexmark(:| ).+_firmware|:wlan_controller_ap_firmware|zyxel(:| ).+_firmware|toshiba(:| ).+_firmware|moxa(:| )(edr|iologik)|sangoma(:| )netborder|" + "silver(-| )peak(:| )(unity_edgeconnect|nx|vx|unknown_model)_sd-wan_firmware|ewon(:| ).+_firmware|optergy(:| )proton(_| )firmware|digitalisierungsbox|base(_| )station(_| )firmware|" + "smartlan(_g_| )firmware|unitronics(_| ).+_firmware|ruckuswireless.+(_| )firmware|ip-ak2(_| )firmware|lancom(:| ).+(_| )firmware|timetools(:| ).+(_| )firmware|" + "unraid:unraid|arubanetworks(:| )instant|arubanetworks:.+(_| )firmware|aruba/hpe.+ firmware|sonicwall(:| )|xerox(:| ).+(_| )firmware|moxa(:| ).+(_| )firmware|circontrol(:| )(circarlife|raption)(_| )firmware|" + "barracuda(:| )load( )?balancer|grandstream(:| ).+(_| )firmware|huawei.+firmware|draytek(:| ).+(_| )firmware|(isilon|powerscale)(_| )onefs|vicon(_| )industries(:| ).+(_| )firmware|" + "auerswald(:| )compact.+firmware|hpe(:| )onboard(_| )administrator(_| )firmware|sophos(:| )sfos|brickcom|xg(:| ).+(_| )firmware|cnpilot.+(_| )firmware|geneko(_| )router|" + "cloudgate.+firmware|sato(:| ).+(_| )firmware|konicaminolta(:| ).+(_| )firmware|gpon(:| ).+(_| )firmware|teltonika(:| ).+(_| )firmware|axis(:| ).+(_| )firmware|znid(_| ).*(_| )firmware|" + "yealink(:| )(vo)?ip(_| )phone|officeconnect.*firewall(_| )software|phoenix(_| )contact(:| ).+firmware|honeywell(:| ).*controller|buffalo(:| ).+firmware|linksys(:| ).+firmware|" + "intel(:| )standard(_| )manageability|mobileiron(:| )(core|sentry)|edgecore(:| )es3526xa|spinetix(:| ).+firmware|ruckus.*(:| )iot(_| )controller|westermo(:| )weos|netgear(:| )|contiki(-| )os|" + "nut(/|_)os|ui(:| ).*(_| )firmware|zyxel(:| ).*firmware|loxone(:| )miniserver|abb(:| ).*firmware|schneider(-| )electric(:| )powerlogic|tp-link(:| ).*firmware|photon(_| )os|avtech|" + "garrettcom(:| )|siemens(:| ).*firmware|flir(:| )(ax8|neco(_| )platform)(_| )firmware|maipu(:| ).*firmware|ibm(:| )global(_| )console|easyio(:| )|(sma_solar_technology_ag|sma solar sunny)|" + "western(_| )digital(:| )my(_| )book(_| )live(_| )firmware|seagate(:| ).*firmware|epson(:| ).+firmware|ruijie(_| )networks(:| ).*firmware)";
	}
	if(eregmatch( pattern: ospattern, string: best_os, icase: TRUE )){
		return "yes";
	}
	return "no";
}
func os_register_and_report( os, version, patch, cpe, banner_type, port, proto, banner, desc, runs_key, full_cpe ){
	var os, version, patch, cpe, banner_type, port, proto, banner, desc, runs_key, full_cpe;
	var oid, malformed_cpe, report, version_lo, patch_lo;
	oid = get_script_oid();
	if(cpe && !get_base_cpe( cpe: cpe )){
		set_kb_item( name: "vt_debug_cpe_syntax/" + get_script_oid(), value: get_script_oid() + "#-#os_register_and_report()#-#" + cpe + "#-#cpe" );
		malformed_cpe = TRUE;
	}
	if(!proto){
		proto = "tcp";
	}
	if(!desc){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#desc#-#os_register_and_report" );
	}
	if( strlen( os ) > 0 ){
		if(strlen( version ) > 0 && tolower( version ) != "unknown" && !ContainsString( os, version )){
			os += " " + version;
		}
		register_host_detail( name: "OS", value: os, desc: desc );
	}
	else {
		os = "N/A";
	}
	report = "OS:           " + os;
	if(version && tolower( version ) != "unknown"){
		version_lo = tolower( version );
		report += "\nVersion:      " + version;
		if(cpe && !full_cpe && !malformed_cpe){
			cpe += ":" + version_lo;
		}
	}
	if(patch && tolower( patch ) != "unknown"){
		patch_lo = tolower( patch );
		report += "\nPatch/Update: " + patch;
		if(cpe && !full_cpe && !malformed_cpe){
			if( version && tolower( version ) != "unknown" ) {
				cpe += ":" + patch_lo;
			}
			else {
				cpe += "::" + patch_lo;
			}
		}
	}
	if( cpe && !malformed_cpe ) {
		register_host_detail( name: "OS", value: cpe, desc: desc );
	}
	else {
		cpe = "N/A";
	}
	report += "\nCPE:          " + cpe;
	report += "\nFound by NVT: " + oid + " (" + desc + ")";
	if(banner_type){
		report += "\nConcluded from " + banner_type;
		if(port && proto != "icmp"){
			report += " on port " + port + "/" + proto;
		}
		if(banner){
			banner = chomp( banner );
			report += ": " + banner;
		}
	}
	if(!port){
		port = "0";
	}
	set_kb_item( name: "os_detection_report/reports/" + oid + "/" + port + "/" + proto, value: report );
	if( !isnull( runs_key ) ) {
		set_kb_item( name: "os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value: runs_key );
	}
	else {
		set_kb_item( name: "os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value: "unknown" );
	}
}
func os_register_unknown_banner( banner, banner_type_name, banner_type_short, port, proto ){
	var banner, banner_type_name, banner_type_short, port, proto;
	var oid;
	oid = get_script_oid();
	if(!banner){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#banner#-#os_register_unknown_banner" );
		return;
	}
	if(!banner_type_name){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#banner_type_name#-#os_register_unknown_banner" );
		return;
	}
	if(!banner_type_short){
		set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#banner_type_short#-#os_register_unknown_banner" );
		return;
	}
	banner = chomp( banner );
	if(banner == "login:" || egrep( pattern: "^MikroTik ", string: banner ) || egrep( pattern: "^[0-9.]+$", string: banner )){
		return;
	}
	if(!proto){
		proto = "tcp";
	}
	if(!port){
		port = "0";
	}
	set_kb_item( name: "os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/banner", value: banner );
	set_kb_item( name: "os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/type_full", value: banner_type_name );
	set_kb_item( name: "unknown_os_or_service/available", value: TRUE );
}
func os_conflict( oslist, bestos ){
	var oslist, bestos, is_cpe, _item;
	is_cpe = FALSE;
	if(ContainsString( bestos, "cpe:/" )){
		is_cpe = TRUE;
	}
	for _item in oslist {
		if(_item == bestos){
			continue;
		}
		if(( ContainsString( _item, "cpe:/" ) ) == is_cpe){
			return TRUE;
		}
	}
	return FALSE;
}
func os_report_best_cpe(  ){
	var best_os_cpe, desc;
	best_os_cpe = os_get_best_cpe();
	if(best_os_cpe){
		desc = get_kb_item( "HostDetails/OS/BestMatchCPE/Details" );
		desc = split( buffer: desc, sep: ";" );
		report_host_detail_single( name: "best_os_cpe", value: best_os_cpe, nvt: desc[0], desc: desc[1] );
	}
	return NULL;
}
func os_report_best_txt(  ){
	var best_os_txt, desc;
	best_os_txt = os_get_best_txt();
	if(best_os_txt){
		desc = get_kb_item( "HostDetails/OS/BestMatchTXT/Details" );
		desc = split( buffer: desc, sep: ";" );
		report_host_detail_single( name: "best_os_txt", value: best_os_txt, nvt: desc[0], desc: desc[1] );
	}
	return NULL;
}
func os_get_cpe_src_list(  ){
	var oid_list;
	oid_list = make_list( "1.3.6.1.4.1.25623.1.0.103220",
		 "1.3.6.1.4.1.25623.1.0.105383",
		 "1.3.6.1.4.1.25623.1.0.103628",
		 "1.3.6.1.4.1.25623.1.0.810231",
		 "1.3.6.1.4.1.25623.1.0.103418",
		 "1.3.6.1.4.1.25623.1.0.103417",
		 "1.3.6.1.4.1.25623.1.0.96206",
		 "1.3.6.1.4.1.25623.1.0.105544",
		 "1.3.6.1.4.1.25623.1.0.105540",
		 "1.3.6.1.4.1.25623.1.0.105690",
		 "1.3.6.1.4.1.25623.1.0.105068",
		 "1.3.6.1.4.1.25623.1.0.105313",
		 "1.3.6.1.4.1.25623.1.0.144208",
		 "1.3.6.1.4.1.25623.1.0.105440",
		 "1.3.6.1.4.1.25623.1.0.105441",
		 "1.3.6.1.4.1.25623.1.0.105433",
		 "1.3.6.1.4.1.25623.1.0.105533",
		 "1.3.6.1.4.1.25623.1.0.105532",
		 "1.3.6.1.4.1.25623.1.0.146071",
		 "1.3.6.1.4.1.25623.1.0.96200",
		 "1.3.6.1.4.1.25623.1.0.105263",
		 "1.3.6.1.4.1.25623.1.0.142605",
		 "1.3.6.1.4.1.25623.1.0.105266",
		 "1.3.6.1.4.1.25623.1.0.106413",
		 "1.3.6.1.4.1.25623.1.0.108566",
		 "1.3.6.1.4.1.25623.1.0.106513",
		 "1.3.6.1.4.1.25623.1.0.105222",
		 "1.3.6.1.4.1.25623.1.0.105033",
		 "1.3.6.1.4.1.25623.1.0.145837",
		 "1.3.6.1.4.1.25623.1.0.105430",
		 "1.3.6.1.4.1.25623.1.0.143118",
		 "1.3.6.1.4.1.25623.1.0.144335",
		 "1.3.6.1.4.1.25623.1.0.106494",
		 "1.3.6.1.4.1.25623.1.0.108307",
		 "1.3.6.1.4.1.25623.1.0.141740",
		 "1.3.6.1.4.1.25623.1.0.146185",
		 "1.3.6.1.4.1.25623.1.0.107228",
		 "1.3.6.1.4.1.25623.1.0.112334",
		 "1.3.6.1.4.1.25623.1.0.141679",
		 "1.3.6.1.4.1.25623.1.0.108311",
		 "1.3.6.1.4.1.25623.1.0.140590",
		 "1.3.6.1.4.1.25623.1.0.144115",
		 "1.3.6.1.4.1.25623.1.0.143245",
		 "1.3.6.1.4.1.25623.1.0.144128",
		 "1.3.6.1.4.1.25623.1.0.810608",
		 "1.3.6.1.4.1.25623.1.0.113169",
		 "1.3.6.1.4.1.25623.1.0.145096",
		 "1.3.6.1.4.1.25623.1.0.144354",
		 "1.3.6.1.4.1.25623.1.0.143523",
		 "1.3.6.1.4.1.25623.1.0.141648",
		 "1.3.6.1.4.1.25623.1.0.106833",
		 "1.3.6.1.4.1.25623.1.0.103710",
		 "1.3.6.1.4.1.25623.1.0.810933",
		 "1.3.6.1.4.1.25623.1.0.105144",
		 "1.3.6.1.4.1.25623.1.0.105659",
		 "1.3.6.1.4.1.25623.1.0.144170",
		 "1.3.6.1.4.1.25623.1.0.144402",
		 "1.3.6.1.4.1.25623.1.0.145983",
		 "1.3.6.1.4.1.25623.1.0.117529",
		 "1.3.6.1.4.1.25623.1.0.117533",
		 "1.3.6.1.4.1.25623.1.0.105625",
		 "1.3.6.1.4.1.25623.1.0.105626",
		 "1.3.6.1.4.1.25623.1.0.105155",
		 "1.3.6.1.4.1.25623.1.0.140058",
		 "1.3.6.1.4.1.25623.1.0.108335",
		 "1.3.6.1.4.1.25623.1.0.105244",
		 "1.3.6.1.4.1.25623.1.0.146362",
		 "1.3.6.1.4.1.25623.1.0.106864",
		 "1.3.6.1.4.1.25623.1.0.106875",
		 "1.3.6.1.4.1.25623.1.0.103875",
		 "1.3.6.1.4.1.25623.1.0.103786",
		 "1.3.6.1.4.1.25623.1.0.142078",
		 "1.3.6.1.4.1.25623.1.0.140995",
		 "1.3.6.1.4.1.25623.1.0.143516",
		 "1.3.6.1.4.1.25623.1.0.103753",
		 "1.3.6.1.4.1.25623.1.0.805964",
		 "1.3.6.1.4.1.25623.1.0.811915",
		 "1.3.6.1.4.1.25623.1.0.144022",
		 "1.3.6.1.4.1.25623.1.0.106151",
		 "1.3.6.1.4.1.25623.1.0.142729",
		 "1.3.6.1.4.1.25623.1.0.106096",
		 "1.3.6.1.4.1.25623.1.0.140738",
		 "1.3.6.1.4.1.25623.1.0.145830",
		 "1.3.6.1.4.1.25623.1.0.140811",
		 "1.3.6.1.4.1.25623.1.0.142907",
		 "1.3.6.1.4.1.25623.1.0.143136",
		 "1.3.6.1.4.1.25623.1.0.144491",
		 "1.3.6.1.4.1.25623.1.0.146123",
		 "1.3.6.1.4.1.25623.1.0.142369",
		 "1.3.6.1.4.1.25623.1.0.20285",
		 "1.3.6.1.4.1.25623.1.0.105176",
		 "1.3.6.1.4.1.25623.1.0.106078",
		 "1.3.6.1.4.1.25623.1.0.108338",
		 "1.3.6.1.4.1.25623.1.0.108347",
		 "1.3.6.1.4.1.25623.1.0.143323",
		 "1.3.6.1.4.1.25623.1.0.143341",
		 "1.3.6.1.4.1.25623.1.0.103910",
		 "1.3.6.1.4.1.25623.1.0.142677",
		 "1.3.6.1.4.1.25623.1.0.143196",
		 "1.3.6.1.4.1.25623.1.0.143419",
		 "1.3.6.1.4.1.25623.1.0.143663",
		 "1.3.6.1.4.1.25623.1.0.103794",
		 "1.3.6.1.4.1.25623.1.0.144339",
		 "1.3.6.1.4.1.25623.1.0.106216",
		 "1.3.6.1.4.1.25623.1.0.113281",
		 "1.3.6.1.4.1.25623.1.0.117074",
		 "1.3.6.1.4.1.25623.1.0.810234",
		 "1.3.6.1.4.1.25623.1.0.812377",
		 "1.3.6.1.4.1.25623.1.0.106015",
		 "1.3.6.1.4.1.25623.1.0.103689",
		 "1.3.6.1.4.1.25623.1.0.113293",
		 "1.3.6.1.4.1.25623.1.0.144537",
		 "1.3.6.1.4.1.25623.1.0.107252",
		 "1.3.6.1.4.1.25623.1.0.144526",
		 "1.3.6.1.4.1.25623.1.0.142867",
		 "1.3.6.1.4.1.25623.1.0.108488",
		 "1.3.6.1.4.1.25623.1.0.112183",
		 "1.3.6.1.4.1.25623.1.0.108491",
		 "1.3.6.1.4.1.25623.1.0.141923",
		 "1.3.6.1.4.1.25623.1.0.143673",
		 "1.3.6.1.4.1.25623.1.0.112339",
		 "1.3.6.1.4.1.25623.1.0.142807",
		 "1.3.6.1.4.1.25623.1.0.141736",
		 "1.3.6.1.4.1.25623.1.0.142838",
		 "1.3.6.1.4.1.25623.1.0.142901",
		 "1.3.6.1.4.1.25623.1.0.141824",
		 "1.3.6.1.4.1.25623.1.0.112774",
		 "1.3.6.1.4.1.25623.1.0.112777",
		 "1.3.6.1.4.1.25623.1.0.146406",
		 "1.3.6.1.4.1.25623.1.0.108494",
		 "1.3.6.1.4.1.25623.1.0.144306",
		 "1.3.6.1.4.1.25623.1.0.141684",
		 "1.3.6.1.4.1.25623.1.0.141766",
		 "1.3.6.1.4.1.25623.1.0.145363",
		 "1.3.6.1.4.1.25623.1.0.141772",
		 "1.3.6.1.4.1.25623.1.0.142010",
		 "1.3.6.1.4.1.25623.1.0.142684",
		 "1.3.6.1.4.1.25623.1.0.141365",
		 "1.3.6.1.4.1.25623.1.0.141174",
		 "1.3.6.1.4.1.25623.1.0.808203",
		 "1.3.6.1.4.1.25623.1.0.145200",
		 "1.3.6.1.4.1.25623.1.0.114075",
		 "1.3.6.1.4.1.25623.1.0.114095",
		 "1.3.6.1.4.1.25623.1.0.114097",
		 "1.3.6.1.4.1.25623.1.0.808237",
		 "1.3.6.1.4.1.25623.1.0.114099",
		 "1.3.6.1.4.1.25623.1.0.114000",
		 "1.3.6.1.4.1.25623.1.0.107335",
		 "1.3.6.1.4.1.25623.1.0.105789",
		 "1.3.6.1.4.1.25623.1.0.106845",
		 "1.3.6.1.4.1.25623.1.0.106844",
		 "1.3.6.1.4.1.25623.1.0.143317",
		 "1.3.6.1.4.1.25623.1.0.143539",
		 "1.3.6.1.4.1.25623.1.0.107120",
		 "1.3.6.1.4.1.25623.1.0.146162",
		 "1.3.6.1.4.1.25623.1.0.143631",
		 "1.3.6.1.4.1.25623.1.0.143704",
		 "1.3.6.1.4.1.25623.1.0.140015",
		 "1.3.6.1.4.1.25623.1.0.143571",
		 "1.3.6.1.4.1.25623.1.0.143598",
		 "1.3.6.1.4.1.25623.1.0.145968",
		 "1.3.6.1.4.1.25623.1.0.146507",
		 "1.3.6.1.4.1.25623.1.0.140631",
		 "1.3.6.1.4.1.25623.1.0.143395",
		 "1.3.6.1.4.1.25623.1.0.113669",
		 "1.3.6.1.4.1.25623.1.0.108940",
		 "1.3.6.1.4.1.25623.1.0.108943",
		 "1.3.6.1.4.1.25623.1.0.145012",
		 "1.3.6.1.4.1.25623.1.0.145014",
		 "1.3.6.1.4.1.25623.1.0.106196",
		 "1.3.6.1.4.1.25623.1.0.145072",
		 "1.3.6.1.4.1.25623.1.0.117491",
		 "1.3.6.1.4.1.25623.1.0.117431",
		 "1.3.6.1.4.1.25623.1.0.117449",
		 "1.3.6.1.4.1.25623.1.0.117452",
		 "1.3.6.1.4.1.25623.1.0.96207",
		 "1.3.6.1.4.1.25623.1.0.112731",
		 "1.3.6.1.4.1.25623.1.0.144459",
		 "1.3.6.1.4.1.25623.1.0.806636",
		 "1.3.6.1.4.1.25623.1.0.146155",
		 "1.3.6.1.4.1.25623.1.0.813817",
		 "1.3.6.1.4.1.25623.1.0.809066",
		 "1.3.6.1.4.1.25623.1.0.50282",
		 "1.3.6.1.4.1.25623.1.0.143355",
		 "1.3.6.1.4.1.25623.1.0.105614",
		 "1.3.6.1.4.1.25623.1.0.146019",
		 "1.3.6.1.4.1.25623.1.0.140454",
		 "1.3.6.1.4.1.25623.1.0.103621",
		 "1.3.6.1.4.1.25623.1.0.112309",
		 "1.3.6.1.4.1.25623.1.0.142731",
		 "1.3.6.1.4.1.25623.1.0.142733",
		 "1.3.6.1.4.1.25623.1.0.108632",
		 "1.3.6.1.4.1.25623.1.0.142756",
		 "1.3.6.1.4.1.25623.1.0.142875",
		 "1.3.6.1.4.1.25623.1.0.143256",
		 "1.3.6.1.4.1.25623.1.0.143512",
		 "1.3.6.1.4.1.25623.1.0.143657",
		 "1.3.6.1.4.1.25623.1.0.112771",
		 "1.3.6.1.4.1.25623.1.0.145540",
		 "1.3.6.1.4.1.25623.1.0.145934",
		 "1.3.6.1.4.1.25623.1.0.105862",
		 "1.3.6.1.4.1.25623.1.0.111015",
		 "1.3.6.1.4.1.25623.1.0.105303",
		 "1.3.6.1.4.1.25623.1.0.105586",
		 "1.3.6.1.4.1.25623.1.0.106030",
		 "1.3.6.1.4.1.25623.1.0.114106",
		 "1.3.6.1.4.1.25623.1.0.142620",
		 "1.3.6.1.4.1.25623.1.0.142850",
		 "1.3.6.1.4.1.25623.1.0.117048",
		 "1.3.6.1.4.1.25623.1.0.143935",
		 "1.3.6.1.4.1.25623.1.0.117270",
		 "1.3.6.1.4.1.25623.1.0.105305",
		 "1.3.6.1.4.1.25623.1.0.113756",
		 "1.3.6.1.4.1.25623.1.0.144350",
		 "1.3.6.1.4.1.25623.1.0.144140",
		 "1.3.6.1.4.1.25623.1.0.144152",
		 "1.3.6.1.4.1.25623.1.0.103809",
		 "1.3.6.1.4.1.25623.1.0.105271",
		 "1.3.6.1.4.1.25623.1.0.810998",
		 "1.3.6.1.4.1.25623.1.0.144564",
		 "1.3.6.1.4.1.25623.1.0.144905",
		 "1.3.6.1.4.1.25623.1.0.144446",
		 "1.3.6.1.4.1.25623.1.0.144575",
		 "1.3.6.1.4.1.25623.1.0.144573",
		 "1.3.6.1.4.1.25623.1.0.103429",
		 "1.3.6.1.4.1.25623.1.0.108014",
		 "1.3.6.1.4.1.25623.1.0.105355",
		 "1.3.6.1.4.1.25623.1.0.102011",
		 "1.3.6.1.4.1.25623.1.0.103979",
		 "1.3.6.1.4.1.25623.1.0.108751",
		 "1.3.6.1.4.1.25623.1.0.111067",
		 "1.3.6.1.4.1.25623.1.0.111068",
		 "1.3.6.1.4.1.25623.1.0.111069",
		 "1.3.6.1.4.1.25623.1.0.108192",
		 "1.3.6.1.4.1.25623.1.0.100292",
		 "1.3.6.1.4.1.25623.1.0.140184",
		 "1.3.6.1.4.1.25623.1.0.108682",
		 "1.3.6.1.4.1.25623.1.0.108590",
		 "1.3.6.1.4.1.25623.1.0.101013",
		 "1.3.6.1.4.1.25623.1.0.10144",
		 "1.3.6.1.4.1.25623.1.0.140000",
		 "1.3.6.1.4.1.25623.1.0.105899",
		 "1.3.6.1.4.1.25623.1.0.108200",
		 "1.3.6.1.4.1.25623.1.0.108201",
		 "1.3.6.1.4.1.25623.1.0.140096",
		 "1.3.6.1.4.1.25623.1.0.100062",
		 "1.3.6.1.4.1.25623.1.0.143777",
		 "1.3.6.1.4.1.25623.1.0.141106",
		 "1.3.6.1.4.1.25623.1.0.107788",
		 "1.3.6.1.4.1.25623.1.0.118034",
		 "1.3.6.1.4.1.25623.1.0.108044",
		 "1.3.6.1.4.1.25623.1.0.103081",
		 "1.3.6.1.4.1.25623.1.0.902058",
		 "1.3.6.1.4.1.25623.1.0.144370",
		 "1.3.6.1.4.1.25623.1.0.108284",
		 "1.3.6.1.4.1.25623.1.0.108565",
		 "1.3.6.1.4.1.25623.1.0.108342",
		 "1.3.6.1.4.1.25623.1.0.105569",
		 "1.3.6.1.4.1.25623.1.0.117275",
		 "1.3.6.1.4.1.25623.1.0.112869",
		 "1.3.6.1.4.1.25623.1.0.141467",
		 "1.3.6.1.4.1.25623.1.0.108451",
		 "1.3.6.1.4.1.25623.1.0.108455",
		 "1.3.6.1.4.1.25623.1.0.106220",
		 "1.3.6.1.4.1.25623.1.0.143411",
		 "1.3.6.1.4.1.25623.1.0.105150",
		 "1.3.6.1.4.1.25623.1.0.103825",
		 "1.3.6.1.4.1.25623.1.0.103841",
		 "1.3.6.1.4.1.25623.1.0.144367",
		 "1.3.6.1.4.1.25623.1.0.100870",
		 "1.3.6.1.4.1.25623.1.0.144839",
		 "1.3.6.1.4.1.25623.1.0.144932",
		 "1.3.6.1.4.1.25623.1.0.112850",
		 "1.3.6.1.4.1.25623.1.0.145038",
		 "1.3.6.1.4.1.25623.1.0.145045",
		 "1.3.6.1.4.1.25623.1.0.145210",
		 "1.3.6.1.4.1.25623.1.0.146403",
		 "1.3.6.1.4.1.25623.1.0.145205",
		 "1.3.6.1.4.1.25623.1.0.145436",
		 "1.3.6.1.4.1.25623.1.0.145298",
		 "1.3.6.1.4.1.25623.1.0.145329",
		 "1.3.6.1.4.1.25623.1.0.145380",
		 "1.3.6.1.4.1.25623.1.0.145395",
		 "1.3.6.1.4.1.25623.1.0.145444",
		 "1.3.6.1.4.1.25623.1.0.145481",
		 "1.3.6.1.4.1.25623.1.0.145485",
		 "1.3.6.1.4.1.25623.1.0.145507",
		 "1.3.6.1.4.1.25623.1.0.112873",
		 "1.3.6.1.4.1.25623.1.0.145601",
		 "1.3.6.1.4.1.25623.1.0.117269",
		 "1.3.6.1.4.1.25623.1.0.145782",
		 "1.3.6.1.4.1.25623.1.0.117421",
		 "1.3.6.1.4.1.25623.1.0.145924",
		 "1.3.6.1.4.1.25623.1.0.145929",
		 "1.3.6.1.4.1.25623.1.0.145946",
		 "1.3.6.1.4.1.25623.1.0.142006",
		 "1.3.6.1.4.1.25623.1.0.146034",
		 "1.3.6.1.4.1.25623.1.0.146046",
		 "1.3.6.1.4.1.25623.1.0.146106",
		 "1.3.6.1.4.1.25623.1.0.146249",
		 "1.3.6.1.4.1.25623.1.0.106738",
		 "1.3.6.1.4.1.25623.1.0.146284",
		 "1.3.6.1.4.1.25623.1.0.146322",
		 "1.3.6.1.4.1.25623.1.0.146387",
		 "1.3.6.1.4.1.25623.1.0.146413",
		 "1.3.6.1.4.1.25623.1.0.146649",
		 "1.3.6.1.4.1.25623.1.0.146718",
		 "1.3.6.1.4.1.25623.1.0.146787",
		 "1.3.6.1.4.1.25623.1.0.146813",
		 "1.3.6.1.4.1.25623.1.0.140134",
		 "1.3.6.1.4.1.25623.1.0.108447",
		 "1.3.6.1.4.1.25623.1.0.10150",
		 "1.3.6.1.4.1.25623.1.0.102002" );
	return oid_list;
}
func os_get_txt_src_list(  ){
	var oid_list;
	oid_list = make_list( "1.3.6.1.4.1.25623.1.0.103220",
		 "1.3.6.1.4.1.25623.1.0.105383",
		 "1.3.6.1.4.1.25623.1.0.103628",
		 "1.3.6.1.4.1.25623.1.0.810231",
		 "1.3.6.1.4.1.25623.1.0.103418",
		 "1.3.6.1.4.1.25623.1.0.103417",
		 "1.3.6.1.4.1.25623.1.0.96206",
		 "1.3.6.1.4.1.25623.1.0.105544",
		 "1.3.6.1.4.1.25623.1.0.105540",
		 "1.3.6.1.4.1.25623.1.0.105690",
		 "1.3.6.1.4.1.25623.1.0.105068",
		 "1.3.6.1.4.1.25623.1.0.105313",
		 "1.3.6.1.4.1.25623.1.0.144208",
		 "1.3.6.1.4.1.25623.1.0.105440",
		 "1.3.6.1.4.1.25623.1.0.105441",
		 "1.3.6.1.4.1.25623.1.0.105433",
		 "1.3.6.1.4.1.25623.1.0.105533",
		 "1.3.6.1.4.1.25623.1.0.105532",
		 "1.3.6.1.4.1.25623.1.0.146071",
		 "1.3.6.1.4.1.25623.1.0.96200",
		 "1.3.6.1.4.1.25623.1.0.105263",
		 "1.3.6.1.4.1.25623.1.0.142605",
		 "1.3.6.1.4.1.25623.1.0.105266",
		 "1.3.6.1.4.1.25623.1.0.106413",
		 "1.3.6.1.4.1.25623.1.0.108566",
		 "1.3.6.1.4.1.25623.1.0.106513",
		 "1.3.6.1.4.1.25623.1.0.105222",
		 "1.3.6.1.4.1.25623.1.0.105033",
		 "1.3.6.1.4.1.25623.1.0.145837",
		 "1.3.6.1.4.1.25623.1.0.105430",
		 "1.3.6.1.4.1.25623.1.0.143118",
		 "1.3.6.1.4.1.25623.1.0.144335",
		 "1.3.6.1.4.1.25623.1.0.106494",
		 "1.3.6.1.4.1.25623.1.0.106875",
		 "1.3.6.1.4.1.25623.1.0.103875",
		 "1.3.6.1.4.1.25623.1.0.103786",
		 "1.3.6.1.4.1.25623.1.0.142078",
		 "1.3.6.1.4.1.25623.1.0.140995",
		 "1.3.6.1.4.1.25623.1.0.143516",
		 "1.3.6.1.4.1.25623.1.0.103753",
		 "1.3.6.1.4.1.25623.1.0.805964",
		 "1.3.6.1.4.1.25623.1.0.811915",
		 "1.3.6.1.4.1.25623.1.0.144022",
		 "1.3.6.1.4.1.25623.1.0.106151",
		 "1.3.6.1.4.1.25623.1.0.142729",
		 "1.3.6.1.4.1.25623.1.0.106096",
		 "1.3.6.1.4.1.25623.1.0.140738",
		 "1.3.6.1.4.1.25623.1.0.145830",
		 "1.3.6.1.4.1.25623.1.0.140811",
		 "1.3.6.1.4.1.25623.1.0.142907",
		 "1.3.6.1.4.1.25623.1.0.143136",
		 "1.3.6.1.4.1.25623.1.0.144491",
		 "1.3.6.1.4.1.25623.1.0.146123",
		 "1.3.6.1.4.1.25623.1.0.142369",
		 "1.3.6.1.4.1.25623.1.0.20285",
		 "1.3.6.1.4.1.25623.1.0.105176",
		 "1.3.6.1.4.1.25623.1.0.106078",
		 "1.3.6.1.4.1.25623.1.0.108307",
		 "1.3.6.1.4.1.25623.1.0.141740",
		 "1.3.6.1.4.1.25623.1.0.146185",
		 "1.3.6.1.4.1.25623.1.0.107228",
		 "1.3.6.1.4.1.25623.1.0.112334",
		 "1.3.6.1.4.1.25623.1.0.141679",
		 "1.3.6.1.4.1.25623.1.0.108311",
		 "1.3.6.1.4.1.25623.1.0.140590",
		 "1.3.6.1.4.1.25623.1.0.144115",
		 "1.3.6.1.4.1.25623.1.0.143245",
		 "1.3.6.1.4.1.25623.1.0.144128",
		 "1.3.6.1.4.1.25623.1.0.810608",
		 "1.3.6.1.4.1.25623.1.0.113169",
		 "1.3.6.1.4.1.25623.1.0.145096",
		 "1.3.6.1.4.1.25623.1.0.144354",
		 "1.3.6.1.4.1.25623.1.0.143523",
		 "1.3.6.1.4.1.25623.1.0.141648",
		 "1.3.6.1.4.1.25623.1.0.106833",
		 "1.3.6.1.4.1.25623.1.0.103710",
		 "1.3.6.1.4.1.25623.1.0.810933",
		 "1.3.6.1.4.1.25623.1.0.105144",
		 "1.3.6.1.4.1.25623.1.0.105659",
		 "1.3.6.1.4.1.25623.1.0.144170",
		 "1.3.6.1.4.1.25623.1.0.144402",
		 "1.3.6.1.4.1.25623.1.0.145983",
		 "1.3.6.1.4.1.25623.1.0.117529",
		 "1.3.6.1.4.1.25623.1.0.117533",
		 "1.3.6.1.4.1.25623.1.0.105625",
		 "1.3.6.1.4.1.25623.1.0.105626",
		 "1.3.6.1.4.1.25623.1.0.105155",
		 "1.3.6.1.4.1.25623.1.0.140058",
		 "1.3.6.1.4.1.25623.1.0.108335",
		 "1.3.6.1.4.1.25623.1.0.105244",
		 "1.3.6.1.4.1.25623.1.0.146362",
		 "1.3.6.1.4.1.25623.1.0.106864",
		 "1.3.6.1.4.1.25623.1.0.108338",
		 "1.3.6.1.4.1.25623.1.0.108347",
		 "1.3.6.1.4.1.25623.1.0.143323",
		 "1.3.6.1.4.1.25623.1.0.143341",
		 "1.3.6.1.4.1.25623.1.0.103910",
		 "1.3.6.1.4.1.25623.1.0.142677",
		 "1.3.6.1.4.1.25623.1.0.143196",
		 "1.3.6.1.4.1.25623.1.0.143419",
		 "1.3.6.1.4.1.25623.1.0.143663",
		 "1.3.6.1.4.1.25623.1.0.103794",
		 "1.3.6.1.4.1.25623.1.0.144339",
		 "1.3.6.1.4.1.25623.1.0.106216",
		 "1.3.6.1.4.1.25623.1.0.113281",
		 "1.3.6.1.4.1.25623.1.0.117074",
		 "1.3.6.1.4.1.25623.1.0.810234",
		 "1.3.6.1.4.1.25623.1.0.812377",
		 "1.3.6.1.4.1.25623.1.0.106015",
		 "1.3.6.1.4.1.25623.1.0.103689",
		 "1.3.6.1.4.1.25623.1.0.113293",
		 "1.3.6.1.4.1.25623.1.0.144537",
		 "1.3.6.1.4.1.25623.1.0.107252",
		 "1.3.6.1.4.1.25623.1.0.144526",
		 "1.3.6.1.4.1.25623.1.0.142867",
		 "1.3.6.1.4.1.25623.1.0.108488",
		 "1.3.6.1.4.1.25623.1.0.112183",
		 "1.3.6.1.4.1.25623.1.0.108491",
		 "1.3.6.1.4.1.25623.1.0.141923",
		 "1.3.6.1.4.1.25623.1.0.143673",
		 "1.3.6.1.4.1.25623.1.0.112339",
		 "1.3.6.1.4.1.25623.1.0.142807",
		 "1.3.6.1.4.1.25623.1.0.141736",
		 "1.3.6.1.4.1.25623.1.0.142838",
		 "1.3.6.1.4.1.25623.1.0.142901",
		 "1.3.6.1.4.1.25623.1.0.141824",
		 "1.3.6.1.4.1.25623.1.0.112774",
		 "1.3.6.1.4.1.25623.1.0.112777",
		 "1.3.6.1.4.1.25623.1.0.146406",
		 "1.3.6.1.4.1.25623.1.0.108494",
		 "1.3.6.1.4.1.25623.1.0.144306",
		 "1.3.6.1.4.1.25623.1.0.141684",
		 "1.3.6.1.4.1.25623.1.0.141766",
		 "1.3.6.1.4.1.25623.1.0.145363",
		 "1.3.6.1.4.1.25623.1.0.141772",
		 "1.3.6.1.4.1.25623.1.0.142010",
		 "1.3.6.1.4.1.25623.1.0.142684",
		 "1.3.6.1.4.1.25623.1.0.141365",
		 "1.3.6.1.4.1.25623.1.0.141174",
		 "1.3.6.1.4.1.25623.1.0.808203",
		 "1.3.6.1.4.1.25623.1.0.145200",
		 "1.3.6.1.4.1.25623.1.0.114075",
		 "1.3.6.1.4.1.25623.1.0.114095",
		 "1.3.6.1.4.1.25623.1.0.114097",
		 "1.3.6.1.4.1.25623.1.0.808237",
		 "1.3.6.1.4.1.25623.1.0.114099",
		 "1.3.6.1.4.1.25623.1.0.114000",
		 "1.3.6.1.4.1.25623.1.0.107335",
		 "1.3.6.1.4.1.25623.1.0.105789",
		 "1.3.6.1.4.1.25623.1.0.106845",
		 "1.3.6.1.4.1.25623.1.0.106844",
		 "1.3.6.1.4.1.25623.1.0.143317",
		 "1.3.6.1.4.1.25623.1.0.143539",
		 "1.3.6.1.4.1.25623.1.0.107120",
		 "1.3.6.1.4.1.25623.1.0.146162",
		 "1.3.6.1.4.1.25623.1.0.143631",
		 "1.3.6.1.4.1.25623.1.0.143704",
		 "1.3.6.1.4.1.25623.1.0.140015",
		 "1.3.6.1.4.1.25623.1.0.143571",
		 "1.3.6.1.4.1.25623.1.0.143598",
		 "1.3.6.1.4.1.25623.1.0.145968",
		 "1.3.6.1.4.1.25623.1.0.146507",
		 "1.3.6.1.4.1.25623.1.0.140631",
		 "1.3.6.1.4.1.25623.1.0.143395",
		 "1.3.6.1.4.1.25623.1.0.113669",
		 "1.3.6.1.4.1.25623.1.0.108940",
		 "1.3.6.1.4.1.25623.1.0.108943",
		 "1.3.6.1.4.1.25623.1.0.145012",
		 "1.3.6.1.4.1.25623.1.0.145014",
		 "1.3.6.1.4.1.25623.1.0.106196",
		 "1.3.6.1.4.1.25623.1.0.145072",
		 "1.3.6.1.4.1.25623.1.0.117491",
		 "1.3.6.1.4.1.25623.1.0.117431",
		 "1.3.6.1.4.1.25623.1.0.117449",
		 "1.3.6.1.4.1.25623.1.0.117452",
		 "1.3.6.1.4.1.25623.1.0.96207",
		 "1.3.6.1.4.1.25623.1.0.112731",
		 "1.3.6.1.4.1.25623.1.0.144459",
		 "1.3.6.1.4.1.25623.1.0.806636",
		 "1.3.6.1.4.1.25623.1.0.146155",
		 "1.3.6.1.4.1.25623.1.0.813817",
		 "1.3.6.1.4.1.25623.1.0.809066",
		 "1.3.6.1.4.1.25623.1.0.50282",
		 "1.3.6.1.4.1.25623.1.0.143355",
		 "1.3.6.1.4.1.25623.1.0.105614",
		 "1.3.6.1.4.1.25623.1.0.146019",
		 "1.3.6.1.4.1.25623.1.0.140454",
		 "1.3.6.1.4.1.25623.1.0.103621",
		 "1.3.6.1.4.1.25623.1.0.112309",
		 "1.3.6.1.4.1.25623.1.0.142731",
		 "1.3.6.1.4.1.25623.1.0.142733",
		 "1.3.6.1.4.1.25623.1.0.108632",
		 "1.3.6.1.4.1.25623.1.0.142756",
		 "1.3.6.1.4.1.25623.1.0.142875",
		 "1.3.6.1.4.1.25623.1.0.143256",
		 "1.3.6.1.4.1.25623.1.0.143512",
		 "1.3.6.1.4.1.25623.1.0.143657",
		 "1.3.6.1.4.1.25623.1.0.112771",
		 "1.3.6.1.4.1.25623.1.0.145540",
		 "1.3.6.1.4.1.25623.1.0.145934",
		 "1.3.6.1.4.1.25623.1.0.105862",
		 "1.3.6.1.4.1.25623.1.0.111015",
		 "1.3.6.1.4.1.25623.1.0.105303",
		 "1.3.6.1.4.1.25623.1.0.105586",
		 "1.3.6.1.4.1.25623.1.0.106030",
		 "1.3.6.1.4.1.25623.1.0.105271",
		 "1.3.6.1.4.1.25623.1.0.810998",
		 "1.3.6.1.4.1.25623.1.0.144564",
		 "1.3.6.1.4.1.25623.1.0.144905",
		 "1.3.6.1.4.1.25623.1.0.144446",
		 "1.3.6.1.4.1.25623.1.0.144575",
		 "1.3.6.1.4.1.25623.1.0.144573",
		 "1.3.6.1.4.1.25623.1.0.114106",
		 "1.3.6.1.4.1.25623.1.0.142620",
		 "1.3.6.1.4.1.25623.1.0.142850",
		 "1.3.6.1.4.1.25623.1.0.117048",
		 "1.3.6.1.4.1.25623.1.0.143935",
		 "1.3.6.1.4.1.25623.1.0.117270",
		 "1.3.6.1.4.1.25623.1.0.105305",
		 "1.3.6.1.4.1.25623.1.0.113756",
		 "1.3.6.1.4.1.25623.1.0.144350",
		 "1.3.6.1.4.1.25623.1.0.144140",
		 "1.3.6.1.4.1.25623.1.0.144152",
		 "1.3.6.1.4.1.25623.1.0.103809",
		 "1.3.6.1.4.1.25623.1.0.103429",
		 "1.3.6.1.4.1.25623.1.0.108014",
		 "1.3.6.1.4.1.25623.1.0.105355",
		 "1.3.6.1.4.1.25623.1.0.102011",
		 "1.3.6.1.4.1.25623.1.0.103979",
		 "1.3.6.1.4.1.25623.1.0.108751",
		 "1.3.6.1.4.1.25623.1.0.111067",
		 "1.3.6.1.4.1.25623.1.0.111068",
		 "1.3.6.1.4.1.25623.1.0.111069",
		 "1.3.6.1.4.1.25623.1.0.108192",
		 "1.3.6.1.4.1.25623.1.0.100292",
		 "1.3.6.1.4.1.25623.1.0.140184",
		 "1.3.6.1.4.1.25623.1.0.108682",
		 "1.3.6.1.4.1.25623.1.0.108590",
		 "1.3.6.1.4.1.25623.1.0.101013",
		 "1.3.6.1.4.1.25623.1.0.10144",
		 "1.3.6.1.4.1.25623.1.0.140000",
		 "1.3.6.1.4.1.25623.1.0.105899",
		 "1.3.6.1.4.1.25623.1.0.108200",
		 "1.3.6.1.4.1.25623.1.0.108201",
		 "1.3.6.1.4.1.25623.1.0.140096",
		 "1.3.6.1.4.1.25623.1.0.100062",
		 "1.3.6.1.4.1.25623.1.0.143777",
		 "1.3.6.1.4.1.25623.1.0.141106",
		 "1.3.6.1.4.1.25623.1.0.107788",
		 "1.3.6.1.4.1.25623.1.0.118034",
		 "1.3.6.1.4.1.25623.1.0.108044",
		 "1.3.6.1.4.1.25623.1.0.103081",
		 "1.3.6.1.4.1.25623.1.0.902058",
		 "1.3.6.1.4.1.25623.1.0.144370",
		 "1.3.6.1.4.1.25623.1.0.108284",
		 "1.3.6.1.4.1.25623.1.0.108565",
		 "1.3.6.1.4.1.25623.1.0.108342",
		 "1.3.6.1.4.1.25623.1.0.105569",
		 "1.3.6.1.4.1.25623.1.0.117275",
		 "1.3.6.1.4.1.25623.1.0.112869",
		 "1.3.6.1.4.1.25623.1.0.141467",
		 "1.3.6.1.4.1.25623.1.0.108451",
		 "1.3.6.1.4.1.25623.1.0.108455",
		 "1.3.6.1.4.1.25623.1.0.106220",
		 "1.3.6.1.4.1.25623.1.0.143411",
		 "1.3.6.1.4.1.25623.1.0.105150",
		 "1.3.6.1.4.1.25623.1.0.103825",
		 "1.3.6.1.4.1.25623.1.0.103841",
		 "1.3.6.1.4.1.25623.1.0.144367",
		 "1.3.6.1.4.1.25623.1.0.100870",
		 "1.3.6.1.4.1.25623.1.0.144839",
		 "1.3.6.1.4.1.25623.1.0.144932",
		 "1.3.6.1.4.1.25623.1.0.112850",
		 "1.3.6.1.4.1.25623.1.0.145038",
		 "1.3.6.1.4.1.25623.1.0.145045",
		 "1.3.6.1.4.1.25623.1.0.145210",
		 "1.3.6.1.4.1.25623.1.0.146403",
		 "1.3.6.1.4.1.25623.1.0.145205",
		 "1.3.6.1.4.1.25623.1.0.145436",
		 "1.3.6.1.4.1.25623.1.0.145298",
		 "1.3.6.1.4.1.25623.1.0.145329",
		 "1.3.6.1.4.1.25623.1.0.145380",
		 "1.3.6.1.4.1.25623.1.0.145395",
		 "1.3.6.1.4.1.25623.1.0.145444",
		 "1.3.6.1.4.1.25623.1.0.145481",
		 "1.3.6.1.4.1.25623.1.0.145485",
		 "1.3.6.1.4.1.25623.1.0.145507",
		 "1.3.6.1.4.1.25623.1.0.112873",
		 "1.3.6.1.4.1.25623.1.0.145601",
		 "1.3.6.1.4.1.25623.1.0.117269",
		 "1.3.6.1.4.1.25623.1.0.145782",
		 "1.3.6.1.4.1.25623.1.0.117421",
		 "1.3.6.1.4.1.25623.1.0.145924",
		 "1.3.6.1.4.1.25623.1.0.145929",
		 "1.3.6.1.4.1.25623.1.0.145946",
		 "1.3.6.1.4.1.25623.1.0.142006",
		 "1.3.6.1.4.1.25623.1.0.146034",
		 "1.3.6.1.4.1.25623.1.0.146046",
		 "1.3.6.1.4.1.25623.1.0.146106",
		 "1.3.6.1.4.1.25623.1.0.146249",
		 "1.3.6.1.4.1.25623.1.0.106738",
		 "1.3.6.1.4.1.25623.1.0.146284",
		 "1.3.6.1.4.1.25623.1.0.146322",
		 "1.3.6.1.4.1.25623.1.0.146387",
		 "1.3.6.1.4.1.25623.1.0.146413",
		 "1.3.6.1.4.1.25623.1.0.146649",
		 "1.3.6.1.4.1.25623.1.0.146718",
		 "1.3.6.1.4.1.25623.1.0.146787",
		 "1.3.6.1.4.1.25623.1.0.146813",
		 "1.3.6.1.4.1.25623.1.0.140134",
		 "1.3.6.1.4.1.25623.1.0.108447",
		 "1.3.6.1.4.1.25623.1.0.10150",
		 "1.3.6.1.4.1.25623.1.0.108021",
		 "1.3.6.1.4.1.25623.1.0.102002" );
	return oid_list;
}

