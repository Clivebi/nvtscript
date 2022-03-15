if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112132" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2017-11-22 11:46:00 +0100 (Wed, 22 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Lantronix Devices Unprotected Telnet Access" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_lantronix_device_version.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "lantronix_device/telnet/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The Lantronix Device Server setup is accessible via an unprotected telnet connection." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to configure and control the device." );
	script_tag( name: "solution", value: "Disable the telnet access or protect it via a strong password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
if(!port = get_kb_item( "lantronix_device/telnet/port" )){
	exit( 0 );
}
banner = telnet_get_banner( port: port );
if(banner && ContainsString( banner, "Press Enter" ) && ContainsString( banner, "Setup Mode" )){
	report = "The Lantronix Device setup menu could be accessed via an unprotected telnet connection.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

