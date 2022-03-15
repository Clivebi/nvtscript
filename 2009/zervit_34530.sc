if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100199" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-14 12:53:07 +0200 (Thu, 14 May 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1353" );
	script_bugtraq_id( 34530, 34570 );
	script_name( "Zervit Webserver multiple vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zervit/banner" );
	script_tag( name: "summary", value: "According to its version number, the remote version of Zervit HTTP
  server is prone to a remote buffer-overflow vulnerability and to a directory-traversal vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit the remote buffer-overflow issue to execute
  arbitrary code within the context of the affected application. Failed exploit attempts will result in
  a denial-of-service condition.

  Exploiting the directory-traversal issue will allow an attacker to view arbitrary local files within the
  context of the webserver. Information harvested may aid in launching further attacks." );
	script_tag( name: "affected", value: "Zervit 0.2, 0.3 and 0.4 are vulnerable. Other versions may also be
  affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34530" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34570" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !egrep( pattern: "Server: Zervit ([0-9.]+)", string: banner )){
	exit( 0 );
}
version = eregmatch( pattern: "Zervit ([0-9.]+)", string: banner );
if(IsMatchRegexp( version[1], "0.(2|3|4)" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

