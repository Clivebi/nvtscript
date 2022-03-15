if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100440" );
	script_version( "2020-12-30T00:35:59+0000" );
	script_tag( name: "last_modification", value: "2020-12-30 00:35:59 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)" );
	script_bugtraq_id( 37715 );
	script_cve_id( "CVE-2009-4489" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Cherokee Terminal Escape Sequence in Logs Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37715" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/508830" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_cherokee_http_detect.sc" );
	script_mandatory_keys( "cherokee/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Cherokee is prone to a command-injection vulnerability because it
  fails to adequately sanitize user-supplied input in logfiles." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands in
  a terminal." );
	script_tag( name: "affected", value: "Cherokee 0.99.30 and prior are vulnerable." );
	exit( 0 );
}
CPE = "cpe:/a:cherokee-project:cherokee";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "0.99.30" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less than or equal to 0.99.30", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

