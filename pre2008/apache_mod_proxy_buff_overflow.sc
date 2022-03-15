if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15555" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 10508 );
	script_cve_id( "CVE-2004-0492" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Apache HTTP Server 'mod_proxy' Content-length Buffer Overflow Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_mandatory_keys( "apache/http_server/detected" );
	script_tag( name: "solution", value: "Don't use mod_proxy or upgrade to a newer version." );
	script_tag( name: "summary", value: "The remote web server appears to be running a version of
  Apache HTTP Server that is older than version 1.3.32.

  This version is vulnerable to a heap based buffer overflow in proxy_util.c
  for mod_proxy." );
	script_tag( name: "impact", value: "This issue may lead remote attackers to cause a denial of
  service and possibly execute arbitrary code on the server." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: version, test_version: "1.3.32" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.32", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

