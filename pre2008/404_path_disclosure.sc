if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11714" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3341, 4035, 4261, 5054, 8075 );
	script_cve_id( "CVE-2003-0456", "CVE-2001-1372" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Non-Existent Page Physical Path Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your server or reconfigure it." );
	script_tag( name: "summary", value: "Your web server reveals the physical path of the webroot
  when asked for a non-existent page.

  Whilst printing errors to the output is useful for debugging applications,
  this feature should not be enabled on production servers." );
	script_tag( name: "affected", value: "Pi3Web version 2.0.0 is known to be vulnerable. Other versions
  might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
exts = make_list( ".",
	 "/",
	 ".html",
	 ".htm",
	 ".jsp",
	 ".shtm",
	 ".shtml",
	 ".cfm" );
asp_exts = make_list( ".asp",
	 ".aspx" );
php_exts = make_list( ".php",
	 ".php3",
	 ".php4",
	 ".php5",
	 ".php7" );
port = http_get_port( default: 80 );
if( http_can_host_asp( port: port ) && http_can_host_php( port: port ) ){
	exts = make_list( exts,
		 asp_exts,
		 php_exts );
}
else {
	if( http_can_host_asp( port: port ) ){
		exts = make_list( exts,
			 asp_exts );
	}
	else {
		if(http_can_host_php( port: port )){
			exts = make_list( exts,
				 php_exts );
		}
	}
}
for ext in exts {
	file = "non-existent-" + rand();
	url = "/" + file + ext;
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(egrep( string: res, pattern: strcat( "[C-H]:(\\\\[A-Za-z0-9_.-])*\\\\", file, "\\\\", ext ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	if(egrep( string: res, pattern: strcat( "(/[A-Za-z0-9_.+-])+/", file, "/", ext ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

