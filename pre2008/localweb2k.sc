if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11005" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2268, 4820, 7947 );
	script_cve_id( "CVE-2001-0189" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "LocalWeb2000 remote read" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Jason Lidow <jason@brandx.net>" );
	script_family( "Remote file access" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "LocalWEB2000/banner" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote host is running LocalWeb2000.

  Version 2.1.0 of LocalWeb2000 allows an attacker to view protected files on the host's computer.

  Example: vulnerableserver.com/./protectedfolder/protectedfile.htm

  It may also disclose the NetBIOS name of the remote host when it receives malformed directory requests." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && egrep( pattern: "^Server: .*LocalWEB2000.*", string: banner, icase: TRUE )){
	security_message( port: port );
}
exit( 0 );

