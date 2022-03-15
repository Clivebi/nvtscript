CPE = "cpe:/a:banu:tinyproxy";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111081" );
	script_version( "$Revision: 12313 $" );
	script_cve_id( "CVE-2012-3505" );
	script_bugtraq_id( 55099 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-01 11:00:00 +0100 (Mon, 01 Feb 2016)" );
	script_name( "Tinyproxy < 1.8.4 Header Multiple Denial of Service Vulnerabilities" );
	script_tag( name: "summary", value: "Tinyproxy is prone to multiple remote denial-of-service
  vulnerabilities that affect the 'OpenSSL' extension." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful attacks will cause the application to consume
  excessive memory, creating a denial-of-service condition." );
	script_tag( name: "affected", value: "Tinyproxy versions before 1.8.4" );
	script_tag( name: "solution", value: "Upgrade to Tinyproxy 1.8.4." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55099" );
	script_xref( name: "URL", value: "https://tinyproxy.github.io/" );
	script_copyright( "This script is Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "sw_tinyproxy_detect.sc" );
	script_mandatory_keys( "tinyproxy/installed" );
	script_require_ports( "Services/http_proxy", 8888 );
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
if(version_is_less( version: vers, test_version: "1.8.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

