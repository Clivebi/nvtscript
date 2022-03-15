if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105246" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2015-04-08 10:07:13 +0200 (Wed, 08 Apr 2015)" );
	script_name( "Trend Micro Interscan Web Security Virtual Appliance Detection (SSH Login)" );
	script_tag( name: "summary", value: "SSH login-based detection of Trend Micro Interscan Web Security Virtual Appliance (IWSVA)." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "IWSVA/system" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!system = get_kb_item( "IWSVA/system" )){
	exit( 0 );
}
if(!ContainsString( system, "IWSVA" )){
	exit( 0 );
}
version = "unknown";
port = get_kb_item( "IWSVA/ssh-login/port" );
set_kb_item( name: "trendmicro/IWSVA/detected", value: TRUE );
set_kb_item( name: "trendmicro/IWSVA/ssh-login/port", value: port );
match = eregmatch( pattern: "IWSVA ([0-9.]+).*_Build_Linux_([0-9]+)", string: system );
if(!isnull( match[1] )){
	version = match[1];
	set_kb_item( name: "trendmicro/IWSVA/ssh-login/" + port + "/concluded", value: match[0] );
}
if(!isnull( match[2] )){
	build = match[2];
}
set_kb_item( name: "trendmicro/IWSVA/ssh-login/" + port + "/version", value: version );
set_kb_item( name: "trendmicro/IWSVA/ssh-login/" + port + "/build", value: build );
exit( 0 );

