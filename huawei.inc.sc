func huawei_is_enterprise_gateway( cpe_string ){
	var cpe_string, match, i;
	match = eregmatch( string: cpe_string, pattern: "(AR12[0-9]-[A-Z])", icase: TRUE );
	if(match){
		return "AR120-S";
	}
	match = eregmatch( string: cpe_string, pattern: "AR150", icase: TRUE );
	if(match){
		return "AR150";
	}
	match = eregmatch( string: cpe_string, pattern: "AR16", icase: TRUE );
	if(match){
		return "AR160";
	}
	match = eregmatch( string: cpe_string, pattern: "AR20", icase: TRUE );
	if(match){
		return "AR200";
	}
	match = eregmatch( string: cpe_string, pattern: "AR51", icase: TRUE );
	if(match){
		return "AR510";
	}
	match = eregmatch( string: cpe_string, pattern: "(AR12[0-9]{2})", icase: TRUE );
	if(match){
		return "AR1200";
	}
	match = eregmatch( string: cpe_string, pattern: "(AR22[0-9]{2})", icase: TRUE );
	if(match){
		return "AR2200";
	}
	match = eregmatch( string: cpe_string, pattern: "AR224", icase: TRUE );
	if(match){
		return "AR2240";
	}
	match = eregmatch( string: cpe_string, pattern: "AR32", icase: TRUE );
	if(match){
		return "AR3200";
	}
	for(i = 1;i < 4;i++){
		match = eregmatch( string: cpe_string, pattern: "SRG" + i + "3", icase: TRUE );
		if(match){
			return "SRG" + i + "300";
		}
	}
	return NULL;
}
func huawei_is_datacenter_switch( cpe_string ){
	var cpe_string, numbers, number, match;
	numbers = make_list( "58",
		 "68",
		 "78",
		 "88",
		 "128",
		 "168" );
	for number in numbers {
		match = eregmatch( string: cpe_string, pattern: "(C[A-Z]*E[A-Z]*(\\s|_)?)" + number, icase: TRUE );
		if(match){
			return "cloudengine_" + number + "00";
		}
	}
	return NULL;
}
func huawei_match_device_in_group( cpe_string, pattern, group, devices ){
	var cpe_string, pattern, group, devices, match, device, match2;
	match = eregmatch( string: cpe_string, pattern: pattern, icase: TRUE );
	if(match){
		for device in devices {
			match2 = eregmatch( string: cpe_string, pattern: device, icase: TRUE );
			if(match2){
				return make_list( group,
					 device );
			}
		}
		return group;
	}
	return NULL;
}
func huawei_is_wlan( cpe_string ){
	var cpe_string, devices, device, match1, pattern, group, ret, match2;
	devices = make_list( "AC6605",
		 "AC6605",
		 "AC6005",
		 "AP430-E",
		 "AT815SN",
		 "R230D-C",
		 "R250D-E",
		 "AD9430DN-12-C",
		 "AD9430DN-24-C",
		 "AD9430DN-24-FAT",
		 "AD9430DN-12-FAT" );
	for device in devices {
		match1 = eregmatch( string: cpe_string, pattern: device, icase: TRUE );
		if(match1){
			return device;
		}
	}
	match1 = eregmatch( string: cpe_string, pattern: "R400", icase: TRUE );
	if(match1){
		return "R450";
	}
	pattern = "AP2[0-9]{3}";
	group = "AP2000";
	devices = make_list( "AP2030DN-C",
		 "AP2050DN",
		 "AP2050DN-E",
		 "AP2050DN-S" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP3[0-9]{3}";
	group = "AP3000";
	devices = make_list( "AP3010DN-AGN",
		 "AP3010DN-AGN-FAT" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP4[0-9]{3}";
	group = "AP4000";
	devices = make_list( "AP4030TN",
		 "AP4030DN-C",
		 "AP4030DN-E-FAT",
		 "AP4050DN-HD",
		 "AP4050DN-E" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP5[0-9]{3}";
	group = "AP5000";
	devices = make_list( "AP5010DN-AGN",
		 "AP5010SN-GN",
		 "AP5010SN-GN-FAT",
		 "AP5010DN-AGN-FAT",
		 "AP5030DN" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP6[0-9]{3}";
	group = "AP6000";
	devices = make_list( "AP6010DN-AGN",
		 "AP6010SN-GN",
		 "AP6050DN",
		 "AP6150DN",
		 "AP6510DN-AGN",
		 "AP6610DN-AGN",
		 "AP6310SN-GN",
		 "AP6010DN-AGN-FAT",
		 "AP6610DN-AGN-FAT",
		 "AP6510DN-AGN-FAT",
		 "AP6010SN-GN-FAT" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP7[0-9]{3}";
	group = "AP7000";
	devices = make_list( "AP7110DN-AGN",
		 "AP7110SN-GN",
		 "AP7050DE",
		 "AP7050DN-E" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP8[0-9]{3}";
	group = "AP8000";
	devices = make_list( "AP8130DN-W",
		 "AP8130DN",
		 "AP9131DN",
		 "AP9131DN-FAT" );
	ret = huawei_match_device_in_group( cpe_string: cpe_string, pattern: pattern, group: group, devices: devices );
	if(ret){
		return ret;
	}
	pattern = "AP9[0-9]{3}";
	group = "AP9000";
	devices = make_list( "AP9131DN",
		 "AP9131DN-FAT" );
	match1 = eregmatch( string: cpe_string, pattern: pattern, icase: TRUE );
	if(match1){
		for device in devices {
			match2 = eregmatch( string: cpe_string, pattern: device, icase: TRUE );
			if(match2){
				return make_list( group,
					 device );
			}
		}
	}
	return ret;
}
func huawei_is_campus_switch( cpe_string ){
	var cpe_string, numbers, number, pattern, match;
	numbers = make_list( "17",
		 "27",
		 "37",
		 "57",
		 "77",
		 "97",
		 "127" );
	for number in numbers {
		pattern = "(((C[A-Z]*(\\s|_)?S[A-Z]*)|S)" + number + "[0-9]{2})";
		match = eregmatch( string: cpe_string, pattern: pattern, icase: TRUE );
		if(match){
			return "S" + number + "00";
		}
	}
	match = eregmatch( string: cpe_string, pattern: "(((C[](\\s|_)?S[])|S)6700)", icase: TRUE );
	if(match){
		return "S6700";
	}
	match = eregmatch( string: cpe_string, pattern: "(((C[](\\s|_)?S[])|S)6720)", icase: TRUE );
	if(match){
		return "S6720";
	}
}
func huawei_find_device( cpe_string ){
	var cpe_string, match, tmp0, tmp1, new_cpe;
	match = NULL;
	match = huawei_is_enterprise_gateway( cpe_string: cpe_string );
	if(!match){
		match = huawei_is_datacenter_switch( cpe_string: cpe_string );
	}
	if(!match){
		match = huawei_is_wlan( cpe_string: cpe_string );
	}
	if(!match){
		match = huawei_is_campus_switch( cpe_string: cpe_string );
	}
	if( match ){
		if( NASLTypeof( match ) == "array" ){
			tmp0 = ereg_replace( string: cpe_string, pattern: "huawei:(.+)_firmware", replace: "huawei:" + tolower( match[0] ) + "_firmware" );
			tmp1 = ereg_replace( string: cpe_string, pattern: "huawei:(.+)_firmware", replace: "huawei:" + tolower( match[1] ) + "_firmware" );
			new_cpe = make_list( tmp0,
				 tmp1 );
		}
		else {
			new_cpe = ereg_replace( string: cpe_string, pattern: "huawei:(.+)_firmware", replace: "huawei:" + tolower( match ) + "_firmware" );
		}
	}
	else {
		return NULL;
	}
	return new_cpe;
}
func huawei_is_yunshan( model, major_version, version ){
	var model, major_version, version;
	if(IsMatchRegexp( major_version, "^5" )){
		return;
	}
	if(IsMatchRegexp( model, "^CE" ) && IsMatchRegexp( version, "^V[3-9]" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
	if(IsMatchRegexp( model, "^CloudEngine\\s+S" ) && IsMatchRegexp( major_version, "^8" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
	if(IsMatchRegexp( model, "^S" ) && IsMatchRegexp( major_version, "^8" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
	if(IsMatchRegexp( model, "^AirEngine" ) && IsMatchRegexp( major_version, "^8" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
	if(IsMatchRegexp( model, "^(USG|Eudemon)" ) && IsMatchRegexp( major_version, "^8" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
	if(IsMatchRegexp( model, "^AR" ) && IsMatchRegexp( version, "^V[3-9]" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
	if(IsMatchRegexp( model, "^NetEngine" ) && IsMatchRegexp( version, "^V[0-9][0-9][0-9]R[0-9][0-9][0-9]C[0-9]1.*$" )){
		set_kb_item( name: "huawei/vrp/yunshan/detected", value: TRUE );
	}
}

