CPE = "cpe:/a:sun:java_system_web_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100703" );
	script_version( "2021-05-03T14:25:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-03 14:25:58 +0000 (Mon, 03 May 2021)" );
	script_tag( name: "creation_date", value: "2010-07-07 12:47:04 +0200 (Wed, 07 Jul 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 41389 );
	script_name( "Sun Java System Web Server Admin Interface DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_sun_oracle_web_server_http_detect.sc" );
	script_mandatory_keys( "sun/java_system_web_server/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/41389" );
	script_tag( name: "summary", value: "Sun Java System Web Server is prone to a denial of service (DoS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to crash the effected application,
  denying service to legitimate users." );
	script_tag( name: "affected", value: "Sun Java System Web Server 7.0 Update 7 is affected. Other versions
  may also be vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
vers = str_replace( find: "U", string: vers, replace: "." );
if(version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "WillNotFix" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

