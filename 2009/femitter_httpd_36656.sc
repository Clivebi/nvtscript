if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100304" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-15 20:14:59 +0200 (Thu, 15 Oct 2009)" );
	script_bugtraq_id( 36656 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Acritum Femitter Server HTTP Request Remote File Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36656" );
	script_tag( name: "summary", value: "Acritum Femitter Server is prone to a remote file-disclosure
  vulnerability because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view the source code of
  the files in the context of the server process. This may aid in
  further attacks." );
	script_tag( name: "affected", value: "Acritum Femitter Server 1.03 is affected. Other versions may be
  vulnerable as well." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
files = http_get_kb_file_extensions( port: port, host: host, ext: "htm*" );
if( !files ){
	file = "/index.htm";
}
else {
	files = make_list( files );
	file = files[0];
}
url = file;
buf = http_get_cache( item: url, port: port );
if(egrep( pattern: "Content-Type", string: buf, icase: TRUE )){
	content_typ = eregmatch( pattern: "Content-Type: ([a-zA-Z/-]+)", string: buf );
	if(content_typ){
		url = NASLString( file, "." );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(!buf){
			exit( 0 );
		}
		if(egrep( pattern: "Content-Type", string: buf, icase: TRUE )){
			content_typ1 = eregmatch( pattern: "Content-Type: ([a-zA-Z/-]+)", string: buf );
			if(!ContainsString( content_typ1[1], content_typ[1] ) && ContainsString( content_typ1[1], "application/binary" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

