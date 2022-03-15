if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103819" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Teles VoIP Devices Default Password" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-24 10:01:48 +0100 (Thu, 24 Oct 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TELES_AG/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration without requiring authentication." );
	script_tag( name: "vuldetect", value: "This check tries to login into the remote Teles device." );
	script_tag( name: "insight", value: "It was possible to login with username 'teles-admin' and password 'tcs-admin'." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "summary", value: "The remote Teles VoIP device is prone to a default account
authentication bypass vulnerability" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: TELES AG" )){
	exit( 0 );
}
host = http_host_name( port: port );
urls = make_list( "/index_vboxgsm.cgi",
	 "/index_abox.cgi",
	 "/index_vbox.cgi",
	 "/index_igate.cgi" );
for url in urls {
	url = "/cgi/" + url;
	req = "GET " + url + " HTTP/1.1\r\nHost: " + host + "\r\n";
	buf = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
	if(!IsMatchRegexp( buf, "HTTP/1.. 401" )){
		continue;
	}
	userpass = "teles-admin:tcs-admin";
	userpass64 = base64( str: userpass );
	req += "Authorization: Basic " + userpass64 + "\r\n\r\n";
	buf = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

