CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10680" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 1193, 1488 );
	script_cve_id( "CVE-2000-0457", "CVE-2000-0630" );
	script_name( "Microsoft Internet Information Services (IIS) Source Fragment Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 Pedro Antonio Nieto Feijoo" );
	script_family( "Remote file access" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-004" );
	script_tag( name: "solution", value: ".htr script mappings should be removed if not required.

  - open Internet Services Manager

  - right click on the web server and select properties

  - select WWW service > Edit > Home Directory > Configuration

  - remove the application mappings reference to .htr

  If .htr functionality is required, install the relevant patches
  from Microsoft (MS01-004)" );
	script_tag( name: "summary", value: "Microsoft IIS 4.0 and 5.0 can be made to disclose
  fragments of source code which should otherwise be
  inaccessible. This is done by appending +.htr to a
  request for a known .asp (or .asa, .ini, etc) file." );
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
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "Microsoft-IIS/[45]\\." )){
	exit( 0 );
}
data = http_get_cache( item: "/", port: port );
if(!data){
	exit( 0 );
}
if(egrep( pattern: "^HTTP/1\\.[01] 40[1-3]", string: data )){
	exit( 0 );
}
if(ContainsString( data, "WWW-Authenticate" )){
	exit( 0 );
}
BaseURL = "";
if(data){
	if(ContainsString( data, "301" ) || ContainsString( data, "302" ) || ContainsString( data, "303" )){
		tmpBaseURL = egrep( pattern: "Location:*", string: data );
		if(tmpBaseURL){
			tmpBaseURL = tmpBaseURL - "Location: ";
			len = strlen( tmpBaseURL );
			strURL = "";
			for(j = 0;j < len;j++){
				strURL = NASLString( strURL, tmpBaseURL[j] );
				if(tmpBaseURL[j] == "/"){
					BaseURL = NASLString( BaseURL, strURL );
					strURL = "";
				}
			}
		}
	}
}
if(BaseURL == ""){
	BaseURL = "/";
}
req = http_get( item: BaseURL, port: port );
data = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!data){
	exit( 0 );
}
if(ereg( pattern: "^HTTP/[0-9]\\.[0-9] 40[13]", string: data )){
	exit( 0 );
}
if(ContainsString( data, "WWW-Authenticate:" )){
	exit( 0 );
}
req = http_get( item: NASLString( BaseURL, "global.asa+.htr" ), port: port );
data = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if( IsMatchRegexp( data, "^HTTP/1\\.[01] 200" ) ){
	if(ContainsString( data, "RUNAT" )){
		report = "We could disclosure the source code of the \"" + BaseURL + "global.asa\" on the remote web server.\n";
		report += "This allows an attacker to gain access to fragments of source code of the remote applications.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if( IsMatchRegexp( data, "^HTTP/1\\.[01] 401" ) ){
		report = "It seems that it's possible to disclose fragments of source code of your web applications which ";
		report += "should otherwise be inaccessible. This is done by appending +.htr to a request for a known .asp (or .asa, .ini, etc) file.";
		security_message( port: port, data: report );
		exit( 0 );
	}
	else {
		if(IsMatchRegexp( data, "^HTTP/1\\.[01] 403" )){
			report = "It seems that it's possible to disclose fragments of source code of your web applications which ";
			report += "should otherwise be inaccessible. This is done by appending +.htr to a request for a known .asp (or .asa, .ini, etc) file.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

