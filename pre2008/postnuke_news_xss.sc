CPE = "cpe:/a:postnuke:postnuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14727" );
	script_version( "$Revision: 14168 $" );
	script_bugtraq_id( 5809 );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Post-Nuke News module XSS" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_dependencies( "secpod_zikula_detect.sc" );
	script_mandatory_keys( "postnuke/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/5809" );
	script_tag( name: "summary", value: "The remote host is running a version of Post-Nuke which contains
  the 'News' module which itself is vulnerable to a cross site scripting issue." );
	script_tag( name: "impact", value: "An attacker may use these flaws to steal the cookies of the
  legitimate users of this web site." );
	script_tag( name: "solution", value: "Upgrade to the latest version of postnuke." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
ver = infos["version"];
dir = infos["location"];
if(version_is_less_equal( version: ver, test_version: "0.721" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "See references", install_path: dir );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

