if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805671" );
	script_version( "2021-03-11T10:58:32+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-07-06 10:15:48 +0530 (Mon, 06 Jul 2015)" );
	script_cve_id( "CVE-2015-5148" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "LivelyCart SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "LivelyCart is prone to an SQL injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the
  response." );
	script_tag( name: "insight", value: "The flaw exists due to the 'search_query'
  parameter in 'product/search' script is not filtering user supplied data." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary SQL commands." );
	script_tag( name: "affected", value: "LivelyCart version 1.2.0 is known to be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37325" );
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
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/livcart", "/cart", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/auth/login", port: port );
	if(ContainsString( res, "Powered by LivelyCart" )){
		url = dir + "/product/search?search_query='";
		if(http_vuln_check( port: port, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

