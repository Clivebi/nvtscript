if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12280" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9921 );
	script_cve_id( "CVE-2004-0174" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Apache HTTP Server Connection Blocking Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Scott Shebby" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_unixoide" );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.0.49 or 1.3.31." );
	script_tag( name: "summary", value: "The remote web server appears to be running a version of
  Apache HTTP Server that is less that 2.0.49 or 1.3.31.

  These versions are vulnerable to a denial of service attack where a remote
  attacker can block new connections to the server by connecting to a listening
  socket on a rarely accessed port." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
CPE = "cpe:/a:apache:http_server";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.3.31" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.31", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.0.0", test_version2: "2.0.48" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.49", install_path: location );
	exit( 0 );
}
exit( 99 );

