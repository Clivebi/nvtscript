if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105221" );
	script_version( "2019-04-18T08:49:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-04-18 08:49:33 +0000 (Thu, 18 Apr 2019)" );
	script_tag( name: "creation_date", value: "2015-02-18 10:02:43 +0100 (Wed, 18 Feb 2015)" );
	script_name( "Forti Authenticator Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "FortiOS/Authenticator/system" );
	script_tag( name: "summary", value: "This script performs SSH based detection of FortiAuthenticator." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("host_details.inc.sc");
system = get_kb_item( "FortiOS/Authenticator/system" );
if(!system){
	exit( 0 );
}
cpe = "cpe:/a:fortinet:fortiauthenticator";
vers = "unknown";
model = eregmatch( string: system, pattern: "Version\\s*:\\s*(FAC[^ ]*)" );
if(!isnull( model[1] )){
	mod = model[1];
	mod = chomp( mod );
	set_kb_item( name: "fortiauthenticator/model", value: mod );
}
version = eregmatch( pattern: "Version\\s*:\\s*FAC[^ ]* v([^-]+)", string: system );
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
	set_kb_item( name: "fortiauthenticator/version", value: v );
	cpe += ":" + v;
	vers = v;
}
b = eregmatch( pattern: "-build([^,]+),", string: system );
if(!isnull( b[1] )){
	build = b[1];
	build = ereg_replace( string: build, pattern: "^0", replace: "" );
	set_kb_item( name: "fortiauthenticator/build", value: build );
}
register_product( cpe: cpe, location: "ssh", service: "ssh" );
report = "Detected FortiAuthenticator (ssh)\n\n" + "Version: " + vers + "\n";
if(mod){
	report += "Model:   " + mod + "\n";
}
if(!isnull( build )){
	report += "Build:   " + build + "\n";
}
report += "CPE:     " + cpe;
log_message( port: 0, data: report );
exit( 0 );

