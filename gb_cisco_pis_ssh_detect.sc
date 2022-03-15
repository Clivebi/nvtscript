if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105612" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-04-20 15:22:13 +0200 (Wed, 20 Apr 2016)" );
	script_name( "Cisco Prime Infrastructure Detection (SSH)" );
	script_tag( name: "summary", value: "This Script performs SSH based detection of Cisco Prime Infrastructure" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "cisco_pis/show_ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
source = "ssh";
if(!system = get_kb_item( "cisco_pis/show_ver" )){
	exit( 0 );
}
if(!ContainsString( system, "Cisco Prime Infrastructure" )){
	exit( 0 );
}
set_kb_item( name: "cisco/pis/detected", value: TRUE );
cpe = "cpe:/a:cisco:prime_infrastructure";
vers = "unknown";
lines = split( system );
for line in lines {
	system -= line;
	if(ContainsString( line, "Cisco Prime Infrastructure" )){
		break;
	}
}
version = eregmatch( pattern: "Version\\s*:\\s*([0-9]+[^\r\n]+)", string: system );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
_build = eregmatch( pattern: "Build\\s*:\\s*([0-9]+[^\r\n]+)", string: system );
if(!isnull( _build[1] )){
	build = _build[1];
	set_kb_item( name: "cisco_pis/" + source + "/build", value: build );
}
if(ContainsString( system, "Critical Fixes:" )){
	lines = split( system );
	for line in lines {
		system -= line;
		if(ContainsString( line, "Critical Fixes:" )){
			break;
		}
	}
	lines = split( system );
	for line in lines {
		if(ContainsString( line, "TECH PACK" )){
			continue;
		}
		if( IsMatchRegexp( line, "PI [0-9]+" ) ){
			_p = eregmatch( pattern: "PI ([0-9]+[^ \r\n(]+) ", string: line );
			if(!isnull( _p[1] )){
				installed_patches += "PI " + _p[1] + "\n";
				if(ContainsString( _p[1], "Update" )){
					pa = eregmatch( pattern: "(^[0-9.]+ )", string: _p[1] );
					if(!isnull( pa[1] )){
						_p[1] = pa[1];
					}
				}
				if( !max_patch_version ) {
					max_patch_version = _p[1];
				}
				else {
					if(version_is_less( version: max_patch_version, test_version: _p[1] )){
						max_patch_version = _p[1];
					}
				}
			}
		}
		else {
			break;
		}
	}
}
if( max_patch_version ){
	set_kb_item( name: "cisco_pis/" + source + "/max_patch_version", value: max_patch_version );
	vers = max_patch_version;
}
else {
	set_kb_item( name: "cisco_pis/" + source + "/max_patch_version", value: "0" );
}
set_kb_item( name: "cisco_pis/" + source + "/version", value: vers );
if(installed_patches){
	set_kb_item( name: "cisco_pis/" + source + "/installed_patches", value: installed_patches );
}
report = "Detected Cisco Prime Infrastructure\n" + "Version: " + vers + "\n" + "Location: " + source + "\n" + "CPE: " + cpe + "\n" + "Concluded: \"" + version[0] + "\"";
if(build){
	report += "\nBuild: " + build;
}
if(max_patch_version){
	report += "\nMax patch version installed: PI " + max_patch_version;
}
if(installed_patches){
	report += "\n\nInstalled patches:\n" + installed_patches + "\n";
}
log_message( port: 0, data: report );
exit( 0 );

