if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14771" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 13777, 13778 );
	script_name( "Apache HTTP Server <= 1.3.33 htpasswd Local Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_mandatory_keys( "apache/http_server/detected" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2004-10/0345.html" );
	script_tag( name: "solution", value: "Update to version 1.3.34 or later." );
	script_tag( name: "summary", value: "The remote host appears to be running Apache HTTP Server
  1.3.33 or older.

  There is a local buffer overflow in the 'htpasswd' command in these versions that may allow
  a local user to gain elevated privileges if 'htpasswd' is run setuid or a remote user to
  run arbitrary commands remotely if the script is accessible through a CGI." );
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
if(version_is_less_equal( version: version, test_version: "1.3.33" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.34", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

