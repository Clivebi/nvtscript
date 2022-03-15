if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801751" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)" );
	script_cve_id( "CVE-2010-4736" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "GateSoft Docusafe 'ECO.asp' SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/27660" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15686/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/96398/gatesafedocusafe-sql.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to allow an attacker
  to obtain sensitive information." );
	script_tag( name: "affected", value: "GateSoft Docusafe 4.2.2 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied
  input via the 'ECO_ID' parameter in 'ECO.asp', which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running GateSoft Docusafe and is prone to SQL
  injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/docusafe", "/DocuSafe", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/main.asp", port: port );
	if(ContainsString( res, "<title>DocuSafe</title>" )){
		url = dir + "/ECO.asp?ECO_ID=' or '1'='1";
		if(http_vuln_check( port: port, url: url, pattern: "Syntax error" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

