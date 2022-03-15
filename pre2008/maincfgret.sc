if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15564" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 11043 );
	script_cve_id( "CVE-2004-0798" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Whatsup Gold vulnerable CGI" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.idefense.com/application/poi/display?id=142&type=vulnerabilities" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.org/0408-advisories/08.25.04.txt" );
	script_tag( name: "solution", value: "Upgrade to Whatsup Gold 8.03 HF 1 or later." );
	script_tag( name: "summary", value: "The '_maincfgret' cgi is installed.

  Some versions were vulnerable to a buffer overflow." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for url in make_list( "/_maincfgret.cgi",
	 "_maincfgret.cgi" ) {
	if(http_is_cgi_installed_ka( item: url, port: port )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

