CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11874" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Microsoft Internet Information Services (IIS) Service Pack - 404" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 SensePost & Copyright (C) 2004 David Maciejak" );
	script_family( "Web Servers" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_tag( name: "solution", value: "The Patch level (Service Pack) of the remote IIS server appears to be lower
  than the current IIS service pack level. As each service pack typically
  contains many security patches, the server may be at risk.

  Caveat: This test makes assumptions of the remote patch level based on static
  return values (Content-Length) within the IIS Servers 404 error message.
  As such, the test can not be totally reliable and should be manually confirmed." );
	script_tag( name: "summary", value: "Ensure that the server is running the latest stable Service Pack" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
sig = http_get_remote_headers( port: port );
if(sig && !ContainsString( sig, "IIS" )){
	exit( 0 );
}
req = http_get( item: "/vttest" + rand(), port: port );
r = http_keepalive_send_recv( data: req, port: port );
if(!r || !ereg( pattern: "^HTTP.* 404 .*", string: r )){
	exit( 0 );
}
v4 = egrep( pattern: "^Server:.*Microsoft-IIS/4\\.0", string: r );
v5 = egrep( pattern: "^Server:.*Microsoft-IIS/5\\.0", string: r );
v51 = egrep( pattern: "^Server:.*Microsoft-IIS/5\\.1", string: r );
v6 = egrep( pattern: "^Server:.*Microsoft-IIS/6\\.0", string: r );
cltmp = eregmatch( pattern: ".*Content-Length: ([0-9]+).*", string: r );
if(isnull( cltmp )){
	exit( 0 );
}
cl = int( cltmp[1] );
ver = NASLString( "The remote IIS server *seems* to be " );
if(v5){
	if(3243 == cl){
		ver += NASLString( "Microsoft IIS 5 - SP0 or SP1\\n" );
	}
	if(2352 == cl){
		ver += NASLString( "Microsoft IIS 5 - SP2 or SRP1\\n" );
	}
	if(4040 == cl){
		ver += NASLString( "Microsoft IIS 5 - SP3 or SP4\\n" );
	}
}
if(v51){
	if(1330 == cl){
		ver += NASLString( "Microsoft IIS 5.1 - SP2\\n" );
	}
	if(4040 == cl){
		ver += NASLString( "Microsoft IIS 5.1 - SP0\\n" );
	}
}
if(v6){
	if(2166 == cl){
		ver += NASLString( "Microsoft IIS 6.0 - SP0\\n" );
	}
	if(1635 == cl){
		ver += NASLString( "Microsoft IIS 6.0 - w2k3 build 3790\\n" );
	}
}
if(ver != "The remote IIS server *seems* to be "){
	security_message( port: port, data: ver );
	exit( 0 );
}
exit( 99 );

