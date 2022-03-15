CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103333" );
	script_bugtraq_id( 50639 );
	script_cve_id( "CVE-2011-4415" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2011-11-15 12:33:51 +0100 (Tue, 15 Nov 2011)" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_name( "Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_mandatory_keys( "apache/http_server/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50639" );
	script_xref( name: "URL", value: "http://www.halfdog.net/Security/2011/ApacheModSetEnvIfIntegerOverflow/" );
	script_xref( name: "URL", value: "http://www.gossamer-threads.com/lists/apache/dev/403775" );
	script_tag( name: "affected", value: "Apache HTTP Server 2.0.x through 2.0.64 and 2.2.x through
  2.2.21 are vulnerable. Other versions may also be affected." );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a local denial-of-service
  vulnerability because of a NULL-pointer dereference error or a memory exhaustion." );
	script_tag( name: "impact", value: "Local attackers can exploit this issue to trigger a NULL-pointer
  dereference or memory exhaustion, and cause a server crash, denying service to legitimate users.

  Note: To trigger this issue, 'mod_setenvif' must be enabled and the attacker should be able
  to place a malicious '.htaccess' file on the affected webserver." );
	script_tag( name: "solution", value: "Update to the most recent version of Apache HTTP Server." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "2.0", test_version2: "2.0.64" ) || version_in_range( version: vers, test_version: "2.2", test_version2: "2.2.21" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

