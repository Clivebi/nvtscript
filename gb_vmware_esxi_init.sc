if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103447" );
	script_version( "2021-09-16T12:48:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:48:59 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-03-14 14:54:53 +0100 (Wed, 14 Mar 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "VMware ESXi scan initialization" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "VMware Local Security Checks" );
	script_dependencies( "gb_vmware_esx_web_detect.sc", "gb_vmware_esxi_authorization.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "VMware/ESX/type/ESXi", "VMware/ESX/port" );
	script_exclude_keys( "global_settings/authenticated_scans_disabled" );
	script_add_preference( name: "ESXi login name:", type: "entry", value: "", id: 1 );
	script_add_preference( name: "ESXi login password:", type: "password", value: "", id: 2 );
	script_tag( name: "summary", value: "This VT initiates an authenticated scan against the VMware ESXi
  SOAP API via HTTP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(get_kb_item( "global_settings/authenticated_scans_disabled" )){
	exit( 0 );
}
require("vmware_esx.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("xml.inc.sc");
port = get_kb_item( "VMware/ESX/port" );
if(!port || !get_port_state( port )){
	exit( 0 );
}
user = get_kb_item( "esxi/login_filled/0" );
if(!user){
	user = script_get_preference( name: "ESXi login name:", id: 1 );
}
pass = get_kb_item( "esxi/password_filled/0" );
if(!pass){
	pass = script_get_preference( name: "ESXi login password:", id: 2 );
}
if(!user || !pass){
	exit( 0 );
}
esxi_version = get_kb_item( "VMware/ESX/version" );
if(!esxi_version){
	log_message( data: "It was NOT possible to retrieve the ESXi version via HTTP. Local Security Checks for ESXi disabled." );
	exit( 0 );
}
if(!IsMatchRegexp( esxi_version, "^[4-7]\\." )){
	log_message( data: "Unsupported ESXi version. Currently ESXi 4.0, 4.1 and 5.0, 5.1, 5.5, 6.0, 6.5, 6.7 and 7.0 are supported. We found ESXi version " + esxi_version );
	register_host_detail( name: "Auth-ESXi-Failure", value: "Protocol ESXi, Port " + port + ", User " + user + " : Unsupported ESXi version." );
	exit( 0 );
}
if(IsMatchRegexp( esxi_version, "^4\\." )){
	if( get_esxi4_x_vibs( port: port, user: user, pass: pass ) ){
		set_kb_item( name: "VMware/ESXi/LSC", value: TRUE );
		set_kb_item( name: "login/ESXi/success", value: TRUE );
		set_kb_item( name: "login/ESXi/success/port", value: port );
		log_message( data: NASLString( "It was possible to login and to get all relevant information from the SOAP API via HTTP. Local Security Checks for ESXi 4.x enabled.\\n\\nThe following bulletins are installed on the remote ESXi:\\n", installed_bulletins ), port: port );
		register_host_detail( name: "Auth-ESXi-Success", value: "Protocol ESXi, Port " + port + ", User " + user );
		exit( 0 );
	}
	else {
		set_kb_item( name: "login/ESXi/failed", value: TRUE );
		set_kb_item( name: "login/ESXi/failed/port", value: port );
		log_message( data: NASLString( "It was NOT possible to login and to get all relevant information from the SOAP API via HTTP. Local Security Checks for ESXi 4.x disabled.\\n\\n", esxi_error ), port: port );
		register_host_detail( name: "Auth-ESXi-Failure", value: "Protocol ESXi, Port " + port + ", User " + user + " : Login failure" );
		exit( 0 );
	}
}
if(IsMatchRegexp( esxi_version, "^[567]\\." )){
	if( get_esxi5_0_vibs( port: port, user: user, pass: pass ) ){
		set_kb_item( name: "VMware/ESXi/LSC", value: TRUE );
		set_kb_item( name: "login/ESXi/success", value: TRUE );
		set_kb_item( name: "login/ESXi/success/port", value: port );
		log_message( data: NASLString( "It was possible to login and to get all relevant information from the SOAP API via HTTP. Local Security Checks for ESXi 5.x/6.x/7.x enabled.\\n\\nThe following bulletins are installed on the remote ESXi:\\n", installed_bulletins ), port: port );
		register_host_detail( name: "Auth-ESXi-Success", value: "Protocol ESXi, Port " + port + ", User " + user );
		exit( 0 );
	}
	else {
		set_kb_item( name: "login/ESXi/failed", value: TRUE );
		set_kb_item( name: "login/ESXi/failed/port", value: port );
		log_message( data: NASLString( "It was NOT possible to login and to get all relevant information from the SOAP API via HTTP. Local Security Checks for ESXi 5.x/6.x/7.x disabled.\\n\\n", esxi_error ), port: port );
		register_host_detail( name: "Auth-ESXi-Failure", value: "Protocol ESXi, Port " + port + ", User " + user + " : Login failure" );
		exit( 0 );
	}
}
exit( 0 );

