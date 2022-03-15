if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105144" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-12-18 17:03:13 +0100 (Thu, 18 Dec 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Citrix Hypervisor / XenServer Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "xenserver/installed" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script performs SSH based detection of Citrix Hypervisor / XenServer." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("ssh_func.inc.sc");
soc = ssh_login_or_reuse_connection();
if(!soc){
	exit( 0 );
}
inventory = ssh_cmd( socket: soc, cmd: "cat /etc/xensource-inventory" );
if(!ContainsString( inventory, "BUILD_NUMBER" ) || !ContainsString( inventory, "PRODUCT_VERSION" )){
	exit( 0 );
}
product_version = "unknown'";
pversion = eregmatch( pattern: "PRODUCT_VERSION='([^']+)'", string: inventory );
if(!isnull( pversion[1] )){
	product_version = pversion[1];
}
build_number = "unknown";
bn = eregmatch( pattern: "BUILD_NUMBER='([^0-9]+)?([^']+)'", string: inventory );
if(!isnull( bn[2] )){
	build_number = bn[2];
}
xen_version = "unknown";
xv = eregmatch( pattern: "XEN_VERSION='([^']+)'", string: inventory );
if(!isnull( xv[1] )){
	xen_version = xv[1];
}
platform_version = "unknown";
pv = eregmatch( pattern: "PLATFORM_VERSION='([^']+)'", string: inventory );
if(!isnull( pv[1] )){
	platform_version = pv[1];
}
kernel_version = "unknown";
kv = eregmatch( pattern: "KERNEL_VERSION='([^']+)'", string: inventory );
if(!isnull( kv[1] )){
	kernel_version = kv[1];
}
control_domain_uuid = "unknown";
cdu = eregmatch( pattern: "CONTROL_DOMAIN_UUID='([^']+)'", string: inventory );
if(!isnull( cdu[1] )){
	control_domain_uuid = cdu[1];
}
p = ssh_cmd( socket: soc, cmd: "xe patch-list params=name-label,hosts" );
if(ContainsString( p, "name-label" )){
	lines = split( buffer: p, keep: FALSE );
	for(x = 0;x < max_index( lines );x++){
		if(IsMatchRegexp( lines[x], "name-label" )){
			if(IsMatchRegexp( lines[x + 1], "hosts.*: $" )){
				patch_uploaded_but_not_applied += lines[x] + "\n";
				continue;
			}
			patches += lines[x] + "\n";
		}
	}
}
close( soc );
if(!patches){
	patches = "No hotfixes installed";
}
set_kb_item( name: "xenserver/patches", value: patches );
set_kb_item( name: "xenserver/product_version", value: product_version );
set_kb_item( name: "xenserver/build_number", value: build_number );
set_kb_item( name: "xenserver/xen_version", value: xen_version );
set_kb_item( name: "xenserver/platform_version", value: platform_version );
set_kb_item( name: "xenserver/kernel_version", value: kernel_version );
set_kb_item( name: "xenserver/control_domain_uuid", value: control_domain_uuid );
if(patch_uploaded_but_not_applied){
	set_kb_item( name: "xenserver/patch_uploaded_but_not_applied", value: patch_uploaded_but_not_applied );
}
os_cpe = build_cpe( value: xen_version, exp: "^([0-9.]+)", base: "cpe:/o:xen:xen:" );
if(!os_cpe){
	os_cpe = "cpe:/o:xen:xen";
}
os_register_and_report( os: "Citrix Hypervisor / XenServer " + product_version, cpe: os_cpe, banner_type: "SSH login", desc: "Citrix Hypervisor / XenServer Detection", runs_key: "unixoide" );
app_cpe = build_cpe( value: product_version, exp: "^([0-9.]+)", base: "cpe:/a:citrix:xenserver:" );
if(!app_cpe){
	app_cpe = "cpe:/a:citrix:xenserver";
}
register_product( cpe: app_cpe, location: "ssh", service: "ssh-login" );
extra = "List of installed hotfixes: \n\n" + patches;
if(patch_uploaded_but_not_applied){
	extra += "\n\nHotfixes uploaded but not installed:\n\n" + patch_uploaded_but_not_applied + "\n";
}
log_message( data: build_detection_report( app: "Citrix Hypervisor / XenServer", version: product_version, install: "/", cpe: app_cpe, extra: extra ), port: 0 );
exit( 0 );

