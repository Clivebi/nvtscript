if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114023" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-08-21 16:35:01 +0200 (Tue, 21 Aug 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Sony Network Camera Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_sony_network_camera_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sony/network_camera/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Sony network cameras use the default credentials admin:admin." );
	script_tag( name: "vuldetect", value: "Tries to login using default credentials." );
	script_tag( name: "affected", value: "All Sony SNC cameras using this web interface." );
	script_tag( name: "solution", value: "Change the default password." );
	script_xref( name: "URL", value: "https://ipvm.com/reports/ip-cameras-default-passwords-directory" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
CPE = "cpe:/h:sony:network_camera";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
username = "admin";
password = "admin";
auth_header = make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: "/command/inquiry.cgi?inqjs=network", add_headers: auth_header );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Dhcp=" ) || ContainsString( res, "DnsAuto=" ) || ContainsString( res, "Ip=" ) || ContainsString( res, "Subnetmask=" ) || ContainsString( res, "Gateway=" )){
	report = "It was possible to login using the username \"" + username + "\" and the password \"" + password + "\".";
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

