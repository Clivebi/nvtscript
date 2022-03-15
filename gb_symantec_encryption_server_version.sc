if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105300" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-06-18 13:47:55 +0200 (Thu, 18 Jun 2015)" );
	script_name( "Symantec Encryption Server Detection" );
	script_tag( name: "summary", value: "This script consolidate SSH/LDAP based detection of Symantec Encryption Server" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc", "gb_symantec_encryption_server_ldap_version.sc" );
	script_mandatory_keys( "symantec_encryption_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "symantec_encryption_server/installed" )){
	exit( 0 );
}
source = "SSH";
cpe = "cpe:/a:symantec:encryption_management_server";
oem_release = get_kb_item( "symantec_encryption_server/oem-release" );
if(oem_release){
	version_build = eregmatch( pattern: "([0-9.]+) \\(Build ([0-9]+)\\)", string: oem_release );
	if(!isnull( version_build[1] )){
		vers = version_build[1];
		cpe += ":" + vers;
	}
	if(!isnull( version_build[2] )){
		build = version_build[2];
	}
}
if(!vers || !build){
	rls = get_kb_item( "symantec_encryption_server/rls" );
	if(rls){
		version_build = eregmatch( pattern: "Symantec Encryption Server release ([^ \r\n]+)", string: rls );
		if(!isnull( version_build[1] )){
			_v = split( buffer: version_build[1], sep: ".", keep: FALSE );
			if(max_index( _v ) == 4){
				if(!vers){
					vers = _v[0] + "." + _v[1] + "." + _v[2];
					cpe += ":" + vers;
				}
				if(!build){
					build = _v[3];
				}
			}
		}
	}
}
if(!vers){
	vers = get_kb_item( "symantec_encryption_server/ldap/version" );
	if(vers){
		source = "LDAP";
		cpe += ":" + vers;
	}
}
if(!build){
	build = get_kb_item( "symantec_encryption_server/ldap/build" );
}
if(vers){
	set_kb_item( name: "symantec_encryption_server/version", value: vers );
}
if(build){
	set_kb_item( name: "symantec_encryption_server/build", value: build );
}
MP = get_kb_item( "symantec_encryption_server/MP" );
_mp = eregmatch( pattern: "MP([0-9]+)", string: MP );
if(!isnull( _mp[1] )){
	mp = _mp[1];
	set_kb_item( name: "symantec_encryption_server/MP_VALUE", value: mp );
}
register_product( cpe: cpe, location: source );
report = "Detected Symantec Encryption Server\n" + "Version:          " + vers + "\n";
if(build){
	report += "Build:            " + build + "\n";
}
if(mp){
	report += "MP:               MP" + mp + "\n";
}
report += "Detection source: " + source + "\n";
log_message( port: 0, data: report );
exit( 0 );

