if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108490" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2018-11-28 14:02:54 +0100 (Wed, 28 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Western Digital My Cloud Products Detection (SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "wd-mycloud/ssh-login/cfg_file" );
	script_tag( name: "summary", value: "SSH login-based detection of Western Digital My Cloud products." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "wd-mycloud/ssh-login/cfg_file" )){
	exit( 0 );
}
if(!port = get_kb_item( "wd-mycloud/ssh-login/port" )){
	exit( 0 );
}
if(!cfg_file = get_kb_item( "wd-mycloud/ssh-login/" + port + "/cfg_file" )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
mod = eregmatch( pattern: "<hw_ver>(WD)?MyCloud([^>]+)</hw_ver>", string: cfg_file );
if(!mod[2]){
	exit( 0 );
}
model = mod[2];
concluded = mod[0];
vers = eregmatch( pattern: "<sw_ver_1>([0-9.]+)</sw_ver_1>", string: cfg_file );
if(vers[1]){
	version = vers[1];
	if(concluded){
		concluded += "\n";
	}
	concluded += vers[0];
}
set_kb_item( name: "wd-mycloud/ssh-login/" + port + "/concluded", value: concluded + "\nfrom \"/etc/NAS_CFG/config.xml\" file." );
set_kb_item( name: "wd-mycloud/detected", value: TRUE );
set_kb_item( name: "wd-mycloud/ssh-login/detected", value: TRUE );
set_kb_item( name: "wd-mycloud/ssh-login/" + port + "/version", value: version );
set_kb_item( name: "wd-mycloud/ssh-login/" + port + "/model", value: model );
exit( 0 );

