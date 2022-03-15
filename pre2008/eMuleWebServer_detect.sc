if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12233" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1892" );
	script_bugtraq_id( 10039 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "eMule Plus Web Server detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 A.Kaverin" );
	script_family( "Peer-To-Peer File Sharing" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "eMule/banner" );
	script_require_ports( 4711 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Disable eMule Web Server or upgrade to a bug-fixed version
  (eMule 0.42e, eMulePlus 1k or later)" );
	script_tag( name: "summary", value: "eMule Web Server works on this port. Some versions of this P2P client
  are vulnerable to a DecodeBase16 buffer overflow which would allow an attacker to execute arbitrary code." );
	script_tag( name: "vuldetect", value: "Note: This script only checks if port 4711 is open and if
  it reports banner which contains string eMule." );
	script_tag( name: "affected", value: "eMule 0.42a-d, eMule 0.30e, eMulePlus <1k" );
	script_xref( name: "URL", value: "http://security.nnov.ru/search/news.asp?binid=3572" );
	exit( 0 );
}
require("http_func.inc.sc");
port = 4711;
if(!get_port_state( port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(banner && ContainsString( banner, "eMule" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

