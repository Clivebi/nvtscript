if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105575" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-09-10T09:51:11+0000" );
	script_tag( name: "last_modification", value: "2020-09-10 09:51:11 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "creation_date", value: "2016-03-17 15:52:18 +0100 (Thu, 17 Mar 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Cisco UCS Director Detection (SSH)" );
	script_tag( name: "summary", value: "SSH based detection of Cisco UCS Director" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco_ucs_director/show_version" );
	exit( 0 );
}
require("host_details.inc.sc");
show_version = get_kb_item( "cisco_ucs_director/show_version" );
if(!show_version){
	exit( 0 );
}
version = "unknown";
build = "unknown";
port = get_kb_item( "cisco_ucs_director/ssh_login/port" );
set_kb_item( name: "cisco/ucs_director/detected", value: TRUE );
set_kb_item( name: "cisco/ucs_director/ssh-login/port", value: port );
set_kb_item( name: "cisco/ucs_director/ssh-login/" + port + "/concluded", value: show_version );
vers = eregmatch( pattern: "Version\\s*:\\s*([0-9.]+)", string: show_version );
if(!isnull( vers[1] )){
	version = vers[1];
}
bld = eregmatch( pattern: "Build Number\\s*:\\s*([0-9]+)", string: show_version );
if(!isnull( bld[1] )){
	build = bld[1];
}
set_kb_item( name: "cisco/ucs_director/ssh-login/" + port + "/version", value: version );
set_kb_item( name: "cisco/ucs_director/ssh-login/" + port + "/build", value: build );
exit( 0 );

