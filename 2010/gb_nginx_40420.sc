CPE = "cpe:/a:nginx:nginx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100659" );
	script_version( "2021-02-01T11:36:44+0000" );
	script_tag( name: "last_modification", value: "2021-02-01 11:36:44 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2010-05-31 18:31:53 +0200 (Mon, 31 May 2010)" );
	script_bugtraq_id( 40420 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "nginx Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40420" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_nginx_consolidation.sc" );
	script_mandatory_keys( "nginx/detected" );
	script_tag( name: "solution", value: "Update to nginx 0.6.37 or later." );
	script_tag( name: "summary", value: "nginx is prone to a directory-traversal vulnerability because it fails
  to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "The issue affects nginx 0.6.36 and prior." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "0.6.36" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.6.37", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

