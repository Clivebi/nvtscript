CPE = "cpe:/a:sun:java_system_web_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800812" );
	script_version( "2021-05-10T14:53:52+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 14:53:52 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1934" );
	script_bugtraq_id( 35204 );
	script_name( "Sun Java System Web Proxy Server 6.1 < 6.1 SP11 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_sun_one_java_sys_web_serv_ssh_login_detect.sc", "gb_sun_oracle_web_server_http_detect.sc" );
	script_mandatory_keys( "sun/java_system_web_server/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35338" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-21-116648-23-1" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-66-259588-1" );
	script_tag( name: "summary", value: "Sun Java Web Server is prone to a cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw is due to error in 'Reverse Proxy Plug-in' which is not
  properly sanitized the input data before being returned to the user. This can be exploited to
  inject arbitrary web script or HTML via the query string in situations that result in a 502
  Gateway error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  code, gain sensitive information by conducting XSS attacks in the context of an affected site." );
	script_tag( name: "affected", value: "Sun Java System Web Server versions 6.1 before 6.1 SP11." );
	script_tag( name: "solution", value: "Update to version 6.1 SP11 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( port: port, cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "6.1", test_version2: "6.1.SP10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.1.SP11", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

