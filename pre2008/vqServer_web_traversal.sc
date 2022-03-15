if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10355" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1067 );
	script_cve_id( "CVE-2000-0240" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "vqServer web traversal vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 SecuriTeam" );
	script_family( "Remote file access" );
	script_dependencies( "gb_vqserver_detect.sc" );
	script_mandatory_keys( "vqserver/detected" );
	script_xref( name: "URL", value: "http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html" );
	script_tag( name: "solution", value: "Upgrade to the latest version available." );
	script_tag( name: "summary", value: "vqSoft's vqServer web server (version 1.9.9 and below) has been detected.

  This version contains a security vulnerability that allows attackers to request any file,
  even if it is outside the HTML directory scope." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
CPE = "cpe:/a:vqsoft:vqserver";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.9.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Update to the latest version.", install_url: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

