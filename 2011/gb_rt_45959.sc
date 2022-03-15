if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103039" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-24 13:11:38 +0100 (Mon, 24 Jan 2011)" );
	script_bugtraq_id( 45959 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-0009" );
	script_name( "Request Tracker Password Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45959" );
	script_xref( name: "URL", value: "http://www.bestpractical.com/rt/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "rt_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "RequestTracker/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Request Tracker is prone to an information-disclosure vulnerability
  because it fails to securely store passwords." );
	script_tag( name: "impact", value: "Successful attacks can allow a local attacker to gain access to the
  stored passwords." );
	script_tag( name: "affected", value: "Request Tracker 3.6.x and 3.8.x are affected. Other versions may also
  be vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "rt_tracker" )){
	if(version_in_range( version: vers, test_version: "3.6", test_version2: "3.6.7" ) || version_in_range( version: vers, test_version: "3.8", test_version2: "3.8.8" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

