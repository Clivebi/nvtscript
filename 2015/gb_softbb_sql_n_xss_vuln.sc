if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805158" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-9560", "CVE-2014-9561" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-02 13:59:06 +0530 (Thu, 02 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "SoftBB 'post' Parameter Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with SoftBB
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not." );
	script_tag( name: "insight", value: "The flaws are due to the
  /redir_last_post_list.php script not properly sanitizing user-supplied
  input to the 'post' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary HTML and script code and inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data." );
	script_tag( name: "affected", value: "SoftBB version 0.1.3, Prior version may
  also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129888" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/softbb", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, "Copyright SoftBB" )){
		url = dir + "/redir_last_post_list.php?post='SQL-INJECTION-TEST";
		if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax", extra_check: "SQL-INJECTION-TEST" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

