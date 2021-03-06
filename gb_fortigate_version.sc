if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105197" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11039 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-17 14:26:47 +0200 (Fri, 17 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2015-02-10 15:03:19 +0100 (Tue, 10 Feb 2015)" );
	script_name( "FortiGate Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of FortiGate" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "FortiOS/system_status" );
	exit( 0 );
}
require("host_details.inc.sc");
system = get_kb_item( "FortiOS/system_status" );
if(!ContainsString( system, "FortiGate" )){
	exit( 0 );
}
set_kb_item( name: "fortigate/system_status", value: system );
cpe = "cpe:/h:fortinet:fortigate";
model = eregmatch( string: system, pattern: "Version: (FortiGate-[^ ]+)" );
if(!isnull( model[1] )){
	mod = model[1];
	set_kb_item( name: "fortigate/model", value: mod );
	cpe += "-" + tolower( mod );
}
vers = "unknown";
version = eregmatch( string: system, pattern: "Version: FortiGate[^ ]* v([^,]+)" );
if(!isnull( version[1] )){
	ver = version[1];
	for(i = 0;i < strlen( ver );i++){
		if(ver[i] == "."){
			continue;
		}
		v += ver[i];
		if(i < ( strlen( ver ) - 1 )){
			v += ".";
		}
	}
	set_kb_item( name: "fortigate/version", value: v );
	cpe += ":" + v;
	vers = v;
}
build = eregmatch( string: system, pattern: ",build([^,]+)" );
if(!isnull( build[1] )){
	build = ereg_replace( string: build[1], pattern: "^0", replace: "" );
	set_kb_item( name: "fortigate/build", value: build );
}
patch = eregmatch( string: system, pattern: "Patch ([0-9]+)" );
if(!isnull( patch[1] )){
	set_kb_item( name: "fortigate/patch", value: patch[1] );
}
register_product( cpe: cpe, location: "ssh" );
report = "Detected FortiGate (ssh)\n\n" + "Version: " + vers + "\n";
if(mod){
	report += "Model:   " + mod + "\n";
}
if(!isnull( build )){
	report += "Build:   " + build + "\n";
}
report += "CPE:     " + cpe;
log_message( port: 0, data: report );
exit( 0 );

