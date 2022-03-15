if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100442" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)" );
	script_bugtraq_id( 37712 );
	script_cve_id( "CVE-2009-4494" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "AOLServer Terminal Escape Sequence in Logs Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37712" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/508830" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_aol_server_detect.sc" );
	script_mandatory_keys( "aol/server/detected" );
	script_tag( name: "summary", value: "AOLServer is prone to a command-injection vulnerability because it
  fails to adequately sanitize user-supplied input in logfiles." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands in
  a terminal." );
	script_tag( name: "affected", value: "AOLServer 4.5.1 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
CPE = "cpe:/a:aol:aolserver";
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
if(version_is_less_equal( version: version, test_version: "4.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Will Not Fix", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

