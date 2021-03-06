CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100084" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)" );
	script_bugtraq_id( 34277 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_name( "Squid Proxy Cache ICAP Adaptation Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_require_ports( "Services/http_proxy", 3128, "Services/www", 8080 );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34277" );
	script_tag( name: "summary", value: "According to its version number, the remote version of Squid
  is prone to a to a remote denial-of-service vulnerability because the proxy server fails to
  adequately bounds-check user-supplied data before copying it to an insufficiently sized buffer." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows remote attackers to
  consume excessive memory, resulting in a denial-of-service condition.

  Note that to exploit this issue, an attacker must be a legitimate
  client user of the proxy." );
	script_tag( name: "affected", value: "The Squid 3.x branch is vulnerable." );
	script_tag( name: "solution", value: "Upgrade to newer version if available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3", test_version2: "3.1.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

