if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113002" );
	script_version( "2021-09-28T12:25:24+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-28 12:25:24 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-26 10:00:00 +0200 (Tue, 26 Sep 2017)" );
	script_name( "Generic HTTP Directory Traversal (Web Application Check)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning" );
	script_xref( name: "URL", value: "https://owasp.org/www-community/attacks/Path_Traversal" );
	script_tag( name: "summary", value: "Generic check for HTTP directory traversal vulnerabilities within
  URL parameters.

  NOTE: Please enable 'Enable generic web application scanning' within the VT 'Global variable
  settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution." );
	script_tag( name: "affected", value: "The following products are known to be affected by the pattern
  and URL parameters checked in this VT:

  - CVE-2019-7254: Linear eMerge E3-Series

  Other products might be affected as well." );
	script_tag( name: "vuldetect", value: "Sends crafted HTTP requests to previously spidered URL
  parameters (e.g. /index.php?parameter=directory_traversal of a web application) and checks the
  response." );
	script_tag( name: "solution", value: "Contact the vendor for a solution." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_timeout( 900 );
	exit( 0 );
}
if(get_kb_item( "global_settings/disable_generic_webapp_scanning" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("list_array_func.inc.sc");
depth = get_kb_item( "global_settings/dir_traversal_depth" );
traversals = traversal_pattern( extra_pattern_list: make_list( "/" ), depth: depth );
files = traversal_files();
count = 0;
max_count = 3;
suffixes = make_list( "",
	 "%23vt/test",
	 "%00" );
prefixes = make_list( "",
	 "c:" );
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
cgis = http_get_kb_cgis( port: port, host: host );
if(!cgis){
	cgis = make_list();
}
cgis = nasl_make_list_unique( cgis, "/ - c []" );
for cgi in cgis {
	cgiArray = split( buffer: cgi, sep: " ", keep: FALSE );
	cgi_vuln = FALSE;
	for traversal in traversals {
		for pattern in keys( files ) {
			file = files[pattern];
			for suffix in suffixes {
				for prefix in prefixes {
					exp = prefix + traversal + file + suffix;
					urls = http_create_exploit_req( cgiArray: cgiArray, ex: exp );
					for url in urls {
						req = http_get( port: port, item: url );
						res = http_keepalive_send_recv( port: port, data: req );
						if(egrep( pattern: pattern, string: res, icase: TRUE )){
							count++;
							cgi_vuln = TRUE;
							vuln += http_report_vuln_url( port: port, url: url ) + "\n\n";
							vuln += "Request:\n" + chomp( req ) + "\n\nResponse:\n" + chomp( res ) + "\n\n\n";
							break;
						}
					}
					if(count >= max_count || cgi_vuln){
						break;
					}
				}
				if(count >= max_count || cgi_vuln){
					break;
				}
			}
			if(count >= max_count || cgi_vuln){
				break;
			}
		}
		if(count >= max_count || cgi_vuln){
			break;
		}
	}
	if(count >= max_count){
		break;
	}
}
if(vuln){
	report = "The following affected URL(s) were found (limited to " + max_count + " results):\n\n" + chomp( vuln );
	security_message( port: port, data: report );
}
exit( 0 );

