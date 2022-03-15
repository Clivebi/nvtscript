CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108550" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-02-19 10:42:10 +0100 (Tue, 19 Feb 2019)" );
	script_name( "Lighttpd < 1.4.51 Multiple Vulnerabilities" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed" );
	script_xref( name: "URL", value: "https://www.lighttpd.net/2018/10/14/1.4.51/" );
	script_tag( name: "summary", value: "This host is running Lighttpd which is prone to
  an information disclosure and authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Lighttpd versions before 1.4.51." );
	script_tag( name: "solution", value: "Upgrade to version 1.4.51 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_less( version: vers, test_version: "1.4.51" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.51" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

