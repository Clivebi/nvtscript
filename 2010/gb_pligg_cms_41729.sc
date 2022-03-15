if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100719" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-16 12:38:11 +0200 (Fri, 16 Jul 2010)" );
	script_bugtraq_id( 41729 );
	script_name( "Pligg 'search.php' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/41729" );
	script_xref( name: "URL", value: "http://www.pligg.com" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/512394" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "pligg_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "pligg/detected" );
	script_tag( name: "summary", value: "Pligg is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Pligg 1.0.4 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "pligg" )){
	if(version_is_equal( version: vers, test_version: "1.0.4" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );
