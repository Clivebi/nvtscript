CPE = "cpe:/o:google:android";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108450" );
	script_version( "2019-09-09T06:03:58+0000" );
	script_tag( name: "last_modification", value: "2019-09-09 06:03:58 +0000 (Mon, 09 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-07-06 14:37:42 +0200 (Fri, 06 Jul 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Android Debug Bridge (ADB) Accessible Without Authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_android_adb_detect.sc" );
	script_mandatory_keys( "adb/noauth" );
	script_xref( name: "URL", value: "https://doublepulsar.com/root-bridge-how-thousands-of-internet-connected-android-devices-now-have-no-security-and-are-b46a68cb0f20" );
	script_xref( name: "URL", value: "https://nelenkov.blogspot.com/2013/02/secure-usb-debugging-in-android-422.html" );
	script_tag( name: "summary", value: "The script checks if the target host is running a service supporting the
  Android Debug Bridge (ADB) protocol without an enabled authentication." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Evaluate if the target host is running a service supporting the
  Android Debug Bridge (ADB) protocol without an enabled authentication." );
	script_tag( name: "solution", value: "Disable the Android Debug Bridge (ADB)protocol within the
  device setting or enable authentication. See the references for more information." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_kb_item( "adb/" + port + "/noauth" )){
	exit( 99 );
}
get_app_location( cpe: CPE, port: port, nofork: TRUE );
security_message( port: port );
exit( 0 );

