if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103049" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-27 12:55:42 +0100 (Thu, 27 Jan 2011)" );
	script_bugtraq_id( 46029 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "PRTG Network Monitor 'errormsg' Parameter Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46029" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to multiple cross-site-scripting
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "PRTG Network Monitor 8.1.2.1809 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 8081 );
if(vers = get_version_from_kb( port: port, app: "prtg_network_monitor" )){
	if(version_is_equal( version: vers, test_version: "8.1.2.1809" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

