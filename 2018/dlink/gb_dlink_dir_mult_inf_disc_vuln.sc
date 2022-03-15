if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113141" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-03-21 10:18:29 +0100 (Wed, 21 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-27 20:30:00 +0000 (Tue, 27 Mar 2018)" );
	script_cve_id( "CVE-2018-6527", "CVE-2018-6528", "CVE-2018-6529" );
	script_name( "D-Link DIR Routers Multiple Information Disclosure Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dir_device", "d-link/dir/fw_version" );
	script_xref( name: "URL", value: "ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-860L/REVA/DIR-860L_REVA_FIRMWARE_PATCH_NOTES_1.11B01_EN_WW.pdf" );
	script_xref( name: "URL", value: "ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-865L/REVA/DIR-865L_REVA_FIRMWARE_PATCH_NOTES_1.10B01_EN_WW.pdf" );
	script_xref( name: "URL", value: "ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-868L/REVA/DIR-868L_REVA_FIRMWARE_PATCH_NOTES_1.20B01_EN_WW.pdf" );
	script_tag( name: "summary", value: "D-Link Routers DIR-860L, DIR-865L and DIR-868L are prone to a cookie disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if the target is an affected device running a vulnerable Firmware version." );
	script_tag( name: "insight", value: "The cookie disclosure can be achieved with a link to soap.cgi, with one of the following crafted parameters:

  deviceid

  receiver

  Treturn" );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to read cookies, such as session cookies." );
	script_tag( name: "affected", value: "D-Link DIR-860L through Firmware version 1.10b04

  D-Link DIR-865L through Firmware version 1.08b01

  D-Link DIR-868L through Firmware version 1.12b04." );
	script_tag( name: "solution", value: "Update to DIR-860L 1.11, DIR-865L 1.10 or DIR-868L 1.20 respectively." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:d-link:dir-860l_firmware",
	 "cpe:/o:d-link:dir-865l_firmware",
	 "cpe:/o:d-link:dir-868l_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!version = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if( ContainsString( cpe, "dir-860l" ) ){
	device = "DIR-860L";
	fixed_ver = "1.11";
}
else {
	if( ContainsString( cpe, "dir-865l" ) ){
		device = "DIR-865L";
		fixed_ver = "1.10";
	}
	else {
		if(ContainsString( cpe, "dir-868l" )){
			device = "DIR-868L";
			fixed_ver = "1.20";
		}
	}
}
if(device && fixed_ver){
	if(version_is_less( version: version, test_version: fixed_ver )){
		report = report_fixed_ver( installed_version: version, fixed_version: fixed_ver, extra: "The target device is a " + device );
		security_message( data: report, port: port );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

