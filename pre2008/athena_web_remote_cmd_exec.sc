if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18376" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9349 );
	script_cve_id( "CVE-2004-1782" );
	script_xref( name: "OSVDB", value: "16861" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Athena Web Registration remote command execution flaw" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote version of tAthena Web server is vulnerable to
  a remote command execution flaw through the athenareg.php script." );
	script_tag( name: "impact", value: "A malicious user could execute arbitrary commands on the remote host." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
http_check_remote_code( check_request: "/athenareg.php?pass=%20;id", check_result: "uid=[0-9]+.*gid=[0-9]+.*", command: "id", port: port );
exit( 99 );

