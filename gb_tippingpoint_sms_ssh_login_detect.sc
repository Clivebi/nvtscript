if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108568" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-04-25 08:00:03 +0000 (Thu, 25 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "TrendMicro TippingPoint Security Management System (SMS) Detection (SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "tippingpoint/sms/ssh-login/version_cmd_or_uname" );
	script_tag( name: "summary", value: "SSH login-based detection of a TrendMicro
  TippingPoint Security Management System (SMS)." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "tippingpoint/sms/ssh-login/version_cmd_or_uname" )){
	exit( 0 );
}
version = "unknown";
port = get_kb_item( "tippingpoint/sms/ssh-login/port" );
vers_cmd = get_kb_item( "tippingpoint/sms/ssh-login/" + port + "/version_cmd" );
uname = get_kb_item( "tippingpoint/sms/ssh-login/" + port + "/uname" );
if(!vers_cmd && !uname){
	exit( 0 );
}
vers = eregmatch( pattern: "Version:\\s+([0-9.]+)", string: vers_cmd );
if( vers[1] ){
	version = vers[1];
	set_kb_item( name: "tippingpoint/sms/ssh-login/" + port + "/concluded", value: vers[0] + " from 'version' command" );
}
else {
	set_kb_item( name: "tippingpoint/sms/ssh-login/" + port + "/concluded", value: uname + " from login banner" );
}
set_kb_item( name: "tippingpoint/sms/detected", value: TRUE );
set_kb_item( name: "tippingpoint/sms/ssh-login/detected", value: TRUE );
set_kb_item( name: "tippingpoint/sms/ssh-login/" + port + "/version", value: version );
exit( 0 );

