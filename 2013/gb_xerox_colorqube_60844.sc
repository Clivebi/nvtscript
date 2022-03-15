if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103806" );
	script_version( "2021-09-06T11:58:24+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:58:24 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-10-11 11:54:40 +0200 (Fri, 11 Oct 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Xerox WorkCentre/ColorQube Multiple Unspecified Security Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_xerox_printer_consolidation.sc" );
	script_mandatory_keys( "xerox/printer/detected" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable firmware version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "summary", value: "Xerox ColorQube is prone to multiple unspecified security vulnerabilities." );
	script_tag( name: "affected", value: "Xerox ColorQube 9303, Xerox ColorQube 9302, Xerox ColorQube 9301 with
  firmware versions < 071.180.203.06400." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60844" );
	script_xref( name: "URL", value: "http://www.xerox.com/download/security/security-bulletin/18344-4e02474da251c/cert_XRX13-006_v1.2.pdf" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:xerox:colorcube_9301_firmware",
	 "cpe:/o:xerox:colorcube_9302_firmware",
	 "cpe:/o:xerox:colorcube_9303_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
version = infos["version"];
if(version_is_less( version: version, test_version: "071.180.203.06400" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "071.180.203.06400" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

