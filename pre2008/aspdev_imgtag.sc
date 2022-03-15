if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18357" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-1008" );
	script_bugtraq_id( 12958 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ASP-DEv XM Forum IMG Tag Script Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "The remote web server contains an ASP script which is vulnerable to a
cross site scripting issue.

Description :

The remote host appears to be running the ASP-DEV XM Forum.

There is a flaw in the remote software which may allow anyone
to inject arbitrary HTML and script code through the BBCode IMG tag
to be executed in a user's browser within the context of the affected
web site." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/default.asp", port: port );
	if(res == NULL){
		continue;
	}
	if(IsMatchRegexp( res, "<a href=\"http://www\\.asp-dev\\.com\">Powered by ASP-DEv XM Forums RC [123]<" )){
		security_message( port );
		exit( 0 );
	}
}

