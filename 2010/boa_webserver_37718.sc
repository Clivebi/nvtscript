if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100443" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)" );
	script_bugtraq_id( 37718 );
	script_cve_id( "CVE-2009-4496" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Boa Webserver Terminal Escape Sequence in Logs Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37718" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/508830" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Boa/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Boa Webserver is prone to a command-injection vulnerability because it
  fails to adequately sanitize user-supplied input in logfiles." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands in
  a terminal." );
	script_tag( name: "affected", value: "Boa Webserver 0.94.14rc21 is vulnerable, other versions may also
  be affected." );
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
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "Boa/", string: banner )){
	version = eregmatch( pattern: "Boa/([0-9.]+[rc0-9]*)", string: banner );
	if(isnull( version[1] )){
		exit( 0 );
	}
	if(version_is_less_equal( version: version[1], test_version: "0.94.14rc21" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

