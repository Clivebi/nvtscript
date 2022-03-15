if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803791" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-6953" );
	script_bugtraq_id( 64635 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-01-08 13:24:03 +0530 (Wed, 08 Jan 2014)" );
	script_name( "BlogEngine.NET 'sioc.axd' Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is running BlogEngine.NET and is prone to information disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to read
  the configuration file." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw is due to an improper access restriction to 'sioc.axd', which
  contains system configuration files." );
	script_tag( name: "affected", value: "BlogEngine.net version 2.8.0.0 and earlier" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary files
  on the target system and obtain valuable information such as access
  credentials." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/553166" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
require("host_details.inc.sc");
benPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/blogengine", "/blog/blogengine", http_cgi_dirs( port: benPort ) ) {
	if(http_vuln_check( port: benPort, url: dir + "/", pattern: ">BlogEngine.NET<", check_header: TRUE )){
		if(http_vuln_check( port: benPort, url: dir + "/sioc.axd", pattern: "sioc:Usergroup>", check_header: TRUE, extra_check: make_list( ">BlogEngine.NET",
			 "sioc_id" ) )){
			security_message( port: benPort );
			exit( 0 );
		}
	}
}
exit( 99 );

