if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143679" );
	script_version( "2021-03-03T13:25:21+0000" );
	script_tag( name: "last_modification", value: "2021-03-03 13:25:21 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-04-08 02:12:28 +0000 (Wed, 08 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Huawei VRP Detection (SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "huawei/vrp/display_version" );
	script_tag( name: "summary", value: "SSH login-based detection of Huawei Versatile Routing Platform (VRP) network devices." );
	exit( 0 );
}
if(!display_version = get_kb_item( "huawei/vrp/display_version" )){
	exit( 0 );
}
port = get_kb_item( "huawei/vrp/ssh/port" );
set_kb_item( name: "huawei/vrp/detected", value: TRUE );
set_kb_item( name: "huawei/vrp/ssh-login/port", value: port );
model = "unknown";
version = "unknown";
patch_version = "unknown";
mod = eregmatch( pattern: "HUAWEI ([^ ]+) ((Terabit )?Routing Switch |Router )?uptime( is)?", string: display_version, icase: TRUE );
if(!isnull( mod[1] )){
	concluded = "\n  - Model:           " + mod[0] + " (truncated)";
	model = mod[1];
}
if(model == "unknown"){
	display_device = get_kb_item( "huawei/vrp/display_device" );
	if(display_device){
		device = egrep( pattern: "(.+)'s Device status:", string: display_device, icase: FALSE );
		if(device){
			mod = eregmatch( pattern: "(.+)'s Device status:", string: device, icase: FALSE );
			if(!isnull( mod[1] )){
				concluded = "\n  - Model:           " + mod[0];
				model = mod[1];
			}
		}
	}
}
vers = eregmatch( pattern: "Version ([0-9.]+)[^\r\n]*(V[0-9A-Z]+)\\)", string: display_version );
if(!isnull( vers[2] )){
	version = vers[2];
	set_kb_item( name: "huawei/vrp/ssh-login/major_version", value: vers[1] );
	concluded += "\n  - Version:         " + vers[0];
}
patch_info = get_kb_item( "huawei/vrp/patch-information" );
pattern = "Patch (version|Package Version)\\s*:.*(V[0-9A-Z]+)";
patch_line = egrep( pattern: pattern, string: patch_info, icase: TRUE );
patch_line = chomp( patch_line );
if( patch_line ){
	patch = eregmatch( pattern: pattern, string: patch_line, icase: TRUE );
	if(!isnull( patch[2] )){
		patch_version = patch[2];
		concluded += "\n  - Installed patch: " + patch[2];
	}
}
else {
	if(ContainsString( patch_info, "Info: No patch exists." )){
		patch_version = "No patch installed";
		concluded += "\n  - Installed patch: \"Info: No patch exists.\"";
	}
}
if(concluded){
	set_kb_item( name: "huawei/vrp/ssh-login/" + port + "/concluded", value: concluded );
}
set_kb_item( name: "huawei/vrp/ssh-login/" + port + "/model", value: model );
set_kb_item( name: "huawei/vrp/ssh-login/" + port + "/version", value: version );
set_kb_item( name: "huawei/vrp/ssh-login/" + port + "/patch", value: patch_version );
exit( 0 );

