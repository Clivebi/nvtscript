if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105420" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 13659 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-27 13:50:19 +0100 (Tue, 27 Oct 2015)" );
	script_name( "Vmware NSX Version Detection (HTTP-API)" );
	script_tag( name: "summary", value: "This script performs HTTP-API based detection of the Vmware NSX Version" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_nsx_webgui_detect.sc", "gather-package-list.sc" );
	script_mandatory_keys( "vmware_nsx/webui" );
	script_exclude_keys( "vmware_nsx/show_ver" );
	script_add_preference( name: "NSX API Username: ", value: "", type: "entry" );
	script_add_preference( name: "NSX API Password: ", type: "password", value: "" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(get_kb_item( "vmware_nsx/show_ver" )){
	exit( 0 );
}
if(!port = get_kb_item( "vmware_nsx/webui/port" )){
	exit( 0 );
}
user = script_get_preference( "NSX API Username: " );
pass = script_get_preference( "NSX API Password: " );
if(!user || !pass){
	exit( 0 );
}
url = "/api/1.0/appliance-management/global/info";
userpass = user + ":" + pass;
userpass64 = base64( str: userpass );
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = "GET " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Authorization: Basic " + userpass64 + "\r\n" + "\r\n";
resp = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( resp, "versionInfo" ) || !ContainsString( resp, "majorVersion" ) || !ContainsString( resp, "minorVersion" )){
	exit( 0 );
}
_major = eregmatch( pattern: "\"majorVersion\":\"([^\"]+)\"", string: resp );
_minor = eregmatch( pattern: "\"minorVersion\":\"([^\"]+)\"", string: resp );
if(isnull( _major[1] ) || isnull( _minor[1] )){
	exit( 0 );
}
_patch = eregmatch( pattern: "\"patchVersion\":\"([^\"]+)\"", string: resp );
_build = eregmatch( pattern: "\"buildNumber\":\"([^\"]+)\"", string: resp );
version = _major[1] + "." + _minor[1];
if(!isnull( _patch[1] )){
	version += "." + _patch[1];
}
set_kb_item( name: "vmware_nsx/http_api/version", value: version );
cpe = "cpe:/a:vmware:nsx:" + version;
if(!isnull( _build[1] )){
	build = _build[1];
	set_kb_item( name: "vmware_nsx/http_api/build", value: build );
}
set_kb_item( name: "vmware_nsx/detected_by", value: "HTTP-API" );
exit( 0 );

