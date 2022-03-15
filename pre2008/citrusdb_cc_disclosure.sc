if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16388" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 12402 );
	script_cve_id( "CVE-2005-0229" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Credit Card Data Disclosure in CitrusDB" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Update to CitrusDB version 0.3.6 or higher and set the
  option '$path_to_ccfile' in the configuration to a path not accessible via HTTP.

  Workaround : Either deny access to the file using access restriction
  features of the remote webserver or change CitrusDB to use a file
  outside the document root and not accessible via HTTP." );
	script_tag( name: "summary", value: "CitrusDB uses a textfile to temporarily store credit card information.

  This textfile is located in the web tree via a static URL and thus accessible to third parties.
  It also isn't deleted after processing resulting in a big window of opportunity for an attacker." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/io", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/newfile.txt";
	req = http_get( item: url, port: port );
	r = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!r){
		continue;
	}
	if(ContainsString( r, "\"CHARGE\",\"" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

