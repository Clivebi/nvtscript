if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103784" );
	script_bugtraq_id( 60480 );
	script_cve_id( "CVE-2013-2338" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-04-01T10:41:43+0000" );
	script_name( "HP Integrated Lights-Out (iLO) Remote Unauthorized Access Vulnerability" );
	script_tag( name: "last_modification", value: "2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-09-10 18:32:43 +0200 (Tue, 10 Sep 2013)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "ilo_detect.sc" );
	script_mandatory_keys( "hp/ilo/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60480" );
	script_tag( name: "impact", value: "A remote attacker can exploit this issue to gain unauthorized administrative
  access to the affected application. Successful exploits will completely compromise the affected computer." );
	script_tag( name: "vuldetect", value: "Check the firmware version." );
	script_tag( name: "insight", value: "An unspecified vulnerability allows remote attackers to execute arbitrary
  code via unknown vectors." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "HP Integrated Lights-Out (iLO) is prone to an unauthorized access
  vulnerability." );
	script_tag( name: "affected", value: "HP Integrated Lights-Out 3 (aka iLO3) with firmware before 1.57 and 4 (aka
  iLO4) with firmware before 1.22, when Single-Sign-On (SSO) is used." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:hp:integrated_lights-out_3_firmware",
	 "cpe:/o:hp:integrated_lights-out_4_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!version = get_app_version( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
if( cpe == "cpe:/o:hp:integrated_lights-out_3_firmware" ){
	if(version_is_less( version: version, test_version: "1.57" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.57" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(cpe == "cpe:/o:hp:integrated_lights-out_4_firmware"){
		if(version_is_less( version: version, test_version: "1.22" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "1.22" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

