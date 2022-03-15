CPE = "cpe:/a:apache:mod_python";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10947" );
	script_version( "2021-07-09T13:04:55+0000" );
	script_tag( name: "last_modification", value: "2021-07-09 13:04:55 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4656 );
	script_cve_id( "CVE-2002-0185" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Apache mod_python Handle Abuse Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Thomas Reinke" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_mod_python_http_detect.sc" );
	script_mandatory_keys( "apache/mod_python/detected" );
	script_tag( name: "summary", value: "Apache mod_python is prone to a handle abuse vulnerability." );
	script_tag( name: "insight", value: "Apache mod_python allows a module which is indirectly imported
  by a published module to then be accessed via the publisher, which allows remote attackers to call
  possibly dangerous functions from the imported module." );
	script_tag( name: "affected", value: "Apache mod_python version 2.7.6 and prior." );
	script_tag( name: "solution", value: "Update to a newer version." );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "2.7.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Unknown", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

