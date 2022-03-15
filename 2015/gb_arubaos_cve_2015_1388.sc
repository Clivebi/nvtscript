CPE = "cpe:/o:arubanetworks:arubaos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105245" );
	script_cve_id( "CVE-2015-1388" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12106 $" );
	script_name( "ArubaOS Remote Access Point (RAP) Command Injection" );
	script_xref( name: "URL", value: "http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2015-004.txt" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The 'RAP console' feature in ArubaOS on Aruba access points in Remote Access Point (AP) mode allows remote
attackers to execute arbitrary commands via unspecified vectors." );
	script_tag( name: "solution", value: "Upgrade to one of the following software versions:

  - ArubaOS 6.3.1.15 or later

  - ArubaOS 6.4.2.4 or later." );
	script_tag( name: "summary", value: "Aruba has identified a problem with the 'RAP Console' feature used in
Aruba access points operating in Remote AP mode." );
	script_tag( name: "affected", value: "- ArubaOS 5.x

  - ArubaOS 6.1.x

  - ArubaOS 6.2.x

  - ArubaOS 6.3 prior to 6.3.1.15

  - ArubaOS 6.4 prior to 6.4.2.4" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-07 14:06:08 +0200 (Tue, 07 Apr 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_arubaos_detect.sc" );
	script_mandatory_keys( "ArubaOS/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	if(!version = get_kb_item( "ArubaOS/version" )){
		exit( 0 );
	}
}
if(version_is_less( version: version, test_version: "6.3" )){
	fix = "6.3.1.15";
}
if(version_in_range( version: version, test_version: "6.3", test_version2: "6.3.1.14" )){
	fix = "6.3.1.15";
}
if(version_in_range( version: version, test_version: "6.4", test_version2: "6.4.2.3" )){
	fix = "6.4.2.4";
}
if(fix){
	model = get_kb_item( "ArubaOS/model" );
	report = "Installed Version: " + version + "\n" + "Fixed Version:     " + fix + "\n";
	if(model){
		report += "Model:             " + model + "\n";
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

