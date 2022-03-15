CPE = "cpe:/a:nginx:nginx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803194" );
	script_version( "2021-02-01T11:36:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-02-01 11:36:44 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2013-04-22 15:03:39 +0530 (Mon, 22 Apr 2013)" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execution arbitrary
  code." );
	script_tag( name: "affected", value: "nginx versions 0.5.x, 0.6.x, 0.7.x to 0.7.65 and 0.8.x to 0.8.37." );
	script_tag( name: "insight", value: "The null bytes are allowed in URIs by default (their presence is indicated
  via a variable named zero_in_uri defined in ngx_http_request.h). Individual modules have the ability to opt-out
  of handling URIs with null bytes." );
	script_tag( name: "solution", value: "Update to nginx 0.7.66 or 0.7.38 or later." );
	script_tag( name: "summary", value: "nginx is prone to an arbitrary code execution vulnerability." );
	script_name( "nginx Arbitrary Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24967/" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/multiple/nginx-06x-arbitrary-code-execution-nullbyte-injection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_nginx_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "nginx/detected", "Host/runs_windows" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "0.7.65" ) || version_in_range( version: version, test_version: "0.8", test_version2: "0.8.37" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

