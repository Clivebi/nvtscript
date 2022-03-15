CPE = "cpe:/a:openwebmail.acatysmoof:openwebmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16463" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2005-0445" );
	script_bugtraq_id( 12547 );
	script_xref( name: "OSVDB", value: "13788" );
	script_name( "Open WebMail Logindomain Parameter Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Web application abuses" );
	script_dependencies( "openwebmail_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OpenWebMail/detected" );
	script_xref( name: "URL", value: "http://openwebmail.org/openwebmail/download/cert/advisories/SA-05:01.txt" );
	script_tag( name: "solution", value: "Upgrade to Open WebMail version 2.50 20040212 or later." );
	script_tag( name: "summary", value: "The remote webmail server is affected by a cross-site scripting flaw.

  The remote host is running at least one instance of Open WebMail that
  fails to sufficiently validate user input supplied to the 'logindomain'
  parameter. This failure enables an attacker to run arbitrary script
  code in the context of a user's web browser." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
magic = "logindomain xss vulnerability";
alt_magic = str_replace( string: magic, find: " ", replace: "%20" );
url = dir + "/openwebmail.pl?logindomain=%22%20/%3E%3Cscript%3Ewindow.alert('" + alt_magic + "')%3C/script%3E";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(isnull( res )){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( string: res, pattern: magic )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

