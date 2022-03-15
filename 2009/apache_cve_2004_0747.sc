CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100172" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-0747" );
	script_bugtraq_id( 11182 );
	script_name( "Apache HTTP Server Configuration File Environment Variable Local Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_mandatory_keys( "apache/http_server/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/11182" );
	script_xref( name: "URL", value: "http://www.apache.org/dist/httpd/Announcement2.html" );
	script_tag( name: "insight", value: "The flaws occurs because the application fails to validate user-supplied
  string lengths before copying them into finite process buffers." );
	script_tag( name: "solution", value: "The vendor has released an upgrade. Please see
  the references for more information." );
	script_tag( name: "summary", value: "According to its version number, the remote version of Apache Web
  Server is prone to a local buffer-overflow vulnerability that
  affects a configuration file environment variable." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary code on
  the affected computer with the privileges of the Apache webserver process." );
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
if(version_is_less( version: vers, test_version: "2.0.51" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.0.51", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

