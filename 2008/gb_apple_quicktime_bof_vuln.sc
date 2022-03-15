CPE = "cpe:/a:apple:quicktime";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800319" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5406" );
	script_bugtraq_id( 32540 );
	script_name( "Apple QuickTime Malformed .mov File Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7296" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/46984" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_apple_quicktime_detection_win_900124.sc" );
	script_mandatory_keys( "QuickTime/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attacker execution of arbitrary codes
  in the context of the affected application and can perform denial of service." );
	script_tag( name: "affected", value: "Apple QuickTime version 7.5.5 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to a failure in handling long arguments on a .mov file." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Apple QuickTime version 7.6.6 or later." );
	script_tag( name: "summary", value: "This host has QuickTime installed, which is prone to Buffer Overflow
  Vulnerability." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.6.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.6.6", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

