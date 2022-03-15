CPE = "cpe:/a:banu:tinyproxy";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111082" );
	script_version( "$Revision: 11922 $" );
	script_cve_id( "CVE-2011-1499", "CVE-2011-1843" );
	script_bugtraq_id( 47276, 47715 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-01 11:00:00 +0100 (Mon, 01 Feb 2016)" );
	script_name( "Tinyproxy < 1.8.3 Multiple Security Bypass Vulnerabilities" );
	script_tag( name: "summary", value: "Tinyproxy is prone to multiple security-bypass vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploits will allow attackers to bypass certain security
  restrictions and gain unauthorized access to the application. This may aid in further attacks." );
	script_tag( name: "affected", value: "Tinyproxy versions before 1.8.3" );
	script_tag( name: "solution", value: "Upgrade to Tinyproxy 1.8.3 or newer." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/47276" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/47715" );
	script_xref( name: "URL", value: "https://tinyproxy.github.io/" );
	script_copyright( "This script is Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
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
if(version_is_less( version: vers, test_version: "1.8.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

