if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146186" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-29 06:29:49 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 20:22:00 +0000 (Thu, 27 May 2021)" );
	script_cve_id( "CVE-2021-33514" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NETGEAR Smart Cloud Switch Command Injection Vulnerability (PSV-2021-0071)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_netgear_smart_cloud_switch_http_detect.sc" );
	script_mandatory_keys( "netgear/smart_cloud_switch/detected" );
	script_tag( name: "summary", value: "Multiple NETGEAR Smart Cloud Switch devices are prone to an
  unauthenticated command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An unauthenticated attacker might inject commands via the
  vulnerable /sqfs/lib/libsal.so.0.0 library used by a CGI application." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://kb.netgear.com/000063641/Security-Advisory-for-Pre-Authentication-Command-Injection-Vulnerability-on-Some-Smart-Switches-PSV-2021-0071" );
	script_xref( name: "URL", value: "https://gynvael.coldwind.pl/?lang=en&id=733" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:netgear:gc108p_firmware",
	 "cpe:/o:netgear:gc108pp_firmware",
	 "cpe:/o:netgear:gs108tv3_firmware",
	 "cpe:/o:netgear:gs110tppv1_firmware",
	 "cpe:/o:netgear:gs110tpv3_firmware",
	 "cpe:/o:netgear:gs110tupv1_firmware",
	 "cpe:/o:netgear:gs710tupv1_firmware",
	 "cpe:/o:netgear:gs716tp_firmware",
	 "cpe:/o:netgear:gs716tpp_firmware",
	 "cpe:/o:netgear:gs728tppv2_firmware",
	 "cpe:/o:netgear:gs728tpv2_firmware",
	 "cpe:/o:netgear:gs752tppv1_firmware",
	 "cpe:/o:netgear:gs752tpv2_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = infos["version"];
if(cpe == "cpe:/o:netgear:gc108p_firmware" || cpe == "cpe:/o:netgear:gc108pp_firmware"){
	if(version_is_less( version: version, test_version: "1.0.7.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.0.7.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:netgear:gs110tupv1_firmware" || cpe == "cpe:/o:netgear:gs710tupv1_firmware"){
	if(version_is_less( version: version, test_version: "1.0.4.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.0.4.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:netgear:gs716tp_firmware" || cpe == "cpe:/o:netgear:gs716tpp_firmware"){
	if(version_is_less( version: version, test_version: "1.0.2.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.0.2.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:netgear:gs108tv3_firmware" || cpe == "cpe:/o:netgear:gs110tppv1_firmware" || cpe == "cpe:/o:netgear:gs110tpv3_firmware"){
	if(version_is_less( version: version, test_version: "7.0.6.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.0.6.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:netgear:gs728tppv2_firmware" || cpe == "cpe:/o:netgear:gs728tpv2_firmware" || cpe == "cpe:/o:netgear:gs752tpv1_firmware" || cpe == "cpe:/o:netgear:gs752tpv2_firmware"){
	if(version_is_less( version: version, test_version: "6.0.6.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.0.6.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

