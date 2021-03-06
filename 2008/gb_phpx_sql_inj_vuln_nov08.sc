if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800134" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5000" );
	script_bugtraq_id( 23033 );
	script_name( "PHPX news_id SQL Injection Vulnerability - Nov08" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32564" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6996" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "affected", value: "PHPX Version 3.5.16 and prior on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to sql commands with uppercase characters passed
  with the news_id parameter to includes/news.inc.php which is not properly sanitised before being used." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running PHPX, which is prone to SQL Injection
  Vulnerability." );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary sql commands.

  NOTE: Vulnerability exists only when magic_quotes_gpc is disabled." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/phpx", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir + "/index.php" ), port: port );
	if(!rcvRes){
		continue;
	}
	if(IsMatchRegexp( rcvRes, "Powered by.+PHPX" )){
		phpxVer = eregmatch( pattern: "PHPX ([0-9.]+)", string: rcvRes );
		if(phpxVer != NULL){
			if(version_is_less_equal( version: phpxVer[1], test_version: "3.5.16" )){
				security_message( port: port );
			}
		}
		exit( 0 );
	}
}
exit( 99 );

