if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902735" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)" );
	script_cve_id( "CVE-2011-3728" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Dolphin '.php' Files Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/Dolphin-7.0.4" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain sensitive
  information." );
	script_tag( name: "affected", value: "Dolphin version 7.0.4" );
	script_tag( name: "insight", value: "The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Dolphin and is prone to information
  disclosure vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
dolPort = http_get_port( default: 80 );
if(!http_can_host_php( port: dolPort )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/dolphin", "/", http_cgi_dirs( port: dolPort ) ) {
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: path + "/index.php", port: dolPort );
	if(ContainsString( rcvRes, "<title>dolphin</title>" )){
		url = path + "/xmlrpc/BxDolXMLRPCProfileView.php";
		if(http_vuln_check( port: dolPort, url: url, pattern: "<b>Fatal error</b>:  " + "require_once\\(\\) \\[<a href='function.require'>function.require</a>\\]:" + " Failed opening required.*xmlrpc/BxDolXMLRPCProfileView.php" )){
			security_message( port: dolPort );
			exit( 0 );
		}
	}
}
exit( 99 );

