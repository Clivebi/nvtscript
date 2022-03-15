if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100005" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)" );
	script_tag( name: "cvss_base", value: "8.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:C" );
	script_cve_id( "CVE-2008-4425" );
	script_bugtraq_id( 30627 );
	script_name( "pPIM Multiple Remote Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.phlatline.org/index.php?page=prod-ppim" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/30627" );
	script_tag( name: "summary", value: "This host is running pPIM which is prone to multiple vulnerabilities, including two security-bypass
  issues, a cross-site scripting issue, and a file-upload issue." );
	script_tag( name: "impact", value: "Attackers can exploit these issues to:

  - execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site

  - steal cookie-based authentication credentials

  - delete local files within the context of the webserver process

  - upload arbitrary PHP scripts and execute them in the context of the webserver

  - change user passwords" );
	script_tag( name: "affected", value: "These issues affect pPIM 1.0 and prior versions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/ppim", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/Readme.txt" );
	buf = http_get_cache( item: url, port: port );
	if( ContainsString( buf, "pPIM" ) ){
		ver = eregmatch( string: buf, pattern: "Version ([0-9\\.0-9]+)" );
		if(!isnull( ver[1] )){
			version = int( str_replace( find: ".", string: ver[1], replace: "" ) );
			if(version > 0 && version <= 10){
				report = report_fixed_ver( installed_version: version, fixed_version: "None" );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
	else {
		url = NASLString( dir, "/upload.php" );
		buf = http_get_cache( item: url, port: port );
		if(!buf){
			continue;
		}
		if( egrep( pattern: "Location:.login\\.php\\?login=1", string: buf ) ){
			url = NASLString( dir, "/upload.php?login=1" );
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(!buf){
				continue;
			}
			if(egrep( pattern: "NAME=\"userfile\"", string: buf ) && egrep( pattern: "name=\"submitupload\"", string: buf )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
		else {
			if(egrep( pattern: "NAME=\"userfile\"", string: buf ) && egrep( pattern: "name=\"submitupload\"", string: buf )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

