CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111109" );
	script_version( "2021-03-05T10:52:42+0000" );
	script_tag( name: "last_modification", value: "2021-03-05 10:52:42 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-07-06 16:00:00 +0200 (Wed, 06 Jul 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Apache HTTP Server 'mod_negotiation' MultiViews Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "webmirror.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_xref( name: "URL", value: "http://www.wisec.it/sectou.php?id=4698ebdc59d15" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "By requesting an invalid 'application/vttest<semicolon> q=1.0'
  Accept: header the webserver is replying with a list of alternative files which exists
  in the webservers directory. See the reference for more background information." );
	script_tag( name: "vuldetect", value: "Check the response if the webserver is disclosing
  alternative files." );
	script_tag( name: "impact", value: "Based on the information provided an attacker might be
  able to bruteforce existing files (like backup files) which exists in the webservers
  directory." );
	script_tag( name: "solution", value: "Disable the MultiViews directive within the webservers
  configuration or don't place files within the webservers directory which shouldn't be
  accessible/guessable by an attacker." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
maxLimit = 10;
curLimit = 0;
vulnReport = make_list();
vuln = FALSE;
host = http_host_name( dont_add_port: TRUE );
for ext in make_list( "php",
	 "html",
	 "txt" ) {
	if(curLimit <= maxLimit){
		break;
	}
	urls = http_get_kb_file_extensions( port: port, host: host, ext: ext );
	if(!urls){
		continue;
	}
	for url in urls {
		if(curLimit >= maxLimit){
			break;
		}
		url = url - "." - ext;
		req = http_get_req( port: port, url: url, accept_header: "application/vttest; q=1.0" );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( res, "HTTP/1\\.[01] 406" ) && ContainsString( res, "Alternates:" )){
			alternatives = egrep( pattern: "<li>.*</li>", string: res );
			vulnReport = make_list( vulnReport,
				 alternatives + "\nat URL: " + http_report_vuln_url( port: port,
				 url: url,
				 url_only: TRUE ) + "\n\n" );
			vuln = TRUE;
			curLimit++;
		}
	}
}
if(vuln){
	report = "By requesting the listed URLs alternative files were identified.\n\n";
	vulnReport = sort( vulnReport );
	for tmp in vulnReport {
		report += tmp;
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

