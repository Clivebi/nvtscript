CPE = "cpe:/a:softaculous:webuzo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103831" );
	script_bugtraq_id( 63483, 63480 );
	script_cve_id( "CVE-2013-6041", "CVE-2013-6042", "CVE-2013-6043" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_name( "Webuzo Cookie Value Handling Remote Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/63483" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-11-13 18:18:47 +0100 (Wed, 13 Nov 2013)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_webuzo_detect.sc" );
	script_require_ports( "Services/www", 2002, 2004 );
	script_mandatory_keys( "webuzo/installed" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to execute arbitrary commands
  in the context of the affected application." );
	script_tag( name: "vuldetect", value: "Check the installed version." );
	script_tag( name: "insight", value: "The value of a cookie used by the application is not
  appropriately validated or sanitised before processing and permits backtick
  characters. This allows additional OS commands to be injected and executed on
  the server system, and may result in server compromise." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Webuzo is prone to a remote command-injection vulnerability because it
  fails to adequately sanitize user-supplied input." );
	script_tag( name: "affected", value: "Webuzo <= 2.1.3 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less_equal( version: vers, test_version: "2.1.3" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 2.1.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

