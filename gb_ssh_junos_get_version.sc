if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96200" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-07-13 11:48:37 +0200 (Wed, 13 Jul 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Get Junos Software Version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "junos/detected" );
	script_tag( name: "summary", value: "This script performs SSH based detection of Junos Software Version." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
soc = ssh_login_or_reuse_connection();
if(!soc){
	exit( 0 );
}
if( get_kb_item( "junos/cli" ) ) {
	sysversion = ssh_cmd( socket: soc, cmd: "show version detail | no-more", nosh: TRUE );
}
else {
	sysversion = ssh_cmd( socket: soc, cmd: "cli show version detail \\| no-more" );
}
if(!sysversion || !ContainsString( sysversion, "JUNOS" )){
	exit( 0 );
}
set_kb_item( name: "junos/show_version", value: sysversion );
v = eregmatch( pattern: "Junos: ([^\r\n]+)", string: sysversion );
if(isnull( v[1] )){
	v = eregmatch( pattern: "KERNEL ([^ ]+) .+on ([0-9]{4}-[0-9]{2}-[0-9]{2})", string: sysversion );
	if(isnull( v[1] )){
		exit( 0 );
	}
}
version = v[1];
b = eregmatch( pattern: "KERNEL ([^ ]+) .+on ([0-9]{4}-[0-9]{2}-[0-9]{2})", string: sysversion );
if(!isnull( b[2] )){
	build = b[2];
}
cpe = "cpe:/o:juniper:junos:" + version;
m = eregmatch( pattern: "Model: ([^\r\n]+)", string: sysversion );
if(!isnull( m[1] )){
	model = m[1];
	set_kb_item( name: "Junos/model", value: model );
}
set_kb_item( name: "Junos/Version", value: version );
set_kb_item( name: "Junos/Build", value: build );
os_register_and_report( os: "JunOS", cpe: cpe, banner_type: "SSH login", desc: "Get Junos Software Version", runs_key: "unixoide" );
register_product( cpe: cpe, location: "ssh" );
report = "Your Junos Version is: " + version + "\n";
if(build){
	report += "Build: " + build + "\n";
}
report += "CPE: " + cpe + "\n";
if(model){
	report += "Model: " + model;
}
log_message( port: 0, data: report );
exit( 0 );

