CPE = "cpe:/a:cesanta:mongoose";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100735" );
	script_version( "2021-07-07T12:08:51+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 12:08:51 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-4535" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Mongoose Web Server <= 2.8 Slash Character Remote File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_mongoose_web_server_http_detect.sc" );
	script_mandatory_keys( "cesanta/mongoose/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Mongoose Web Server is prone to a remote file-disclosure
  vulnerability because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to view the source
  code of files in the context of the server process, which may aid in further attacks." );
	script_tag( name: "affected", value: "This issue affects Mongoose Web Server version 2.8. Other
  versions may be vulnerable as well." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42051" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
phps = http_get_kb_file_extensions( port: port, host: host, ext: "php" );
if( !isnull( phps ) ){
	phps = make_list( phps );
}
else {
	phps = make_list( "/index.php" );
}
x = 0;
for php in phps {
	x++;
	url = php + "/";
	if(buf = http_vuln_check( port: port, url: url, pattern: "<\\?(php)?", check_header: TRUE )){
		if(ContainsString( buf, "Content-Type: text/plain" )){
			if(!http_vuln_check( port: port, url: php, pattern: "<\\?(php)?" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
	if(x >= 3){
		exit( 0 );
	}
}
exit( 99 );

