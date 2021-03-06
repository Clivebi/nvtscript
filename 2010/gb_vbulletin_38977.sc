CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100557" );
	script_version( "2019-09-27T07:10:39+0000" );
	script_tag( name: "last_modification", value: "2019-09-27 07:10:39 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2010-03-29 12:55:36 +0200 (Mon, 29 Mar 2010)" );
	script_bugtraq_id( 38977 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "vBulletin Multiple Unspecified Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38977" );
	script_xref( name: "URL", value: "http://www.vbulletin.com/forum/showthread.php?346761-Security-Patch-Release-4.0.2-PL3" );
	script_xref( name: "URL", value: "http://www.vbulletin.com/forum/showthread.php?346897-Security-Patch-Release-4.0.2-PL4" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "solution", value: "The vendor released updates to address these issues. Please see the
  references for more information." );
	script_tag( name: "summary", value: "vBulletin is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "vBulletin versions prior to 4.0.2 PL4 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "4.0.2.PL4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.0.2 PL4", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

