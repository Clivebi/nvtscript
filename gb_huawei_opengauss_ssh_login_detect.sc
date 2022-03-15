if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108973" );
	script_version( "2021-07-20T12:03:58+0000" );
	script_tag( name: "last_modification", value: "2021-07-20 12:03:58 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-10-26 07:21:21 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Huawei openGauss Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "SSH login-based detection of Huawei openGauss." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
if(get_kb_item( "ssh/login/gaussdb_gsql_bins/" + port + "/not_found" )){
	ssh_close_connection();
	exit( 0 );
}
if( get_kb_item( "ssh/login/gaussdb_gsql_bins/" + port + "/found" ) ){
	bins = get_kb_list( "ssh/login/gaussdb_gsql_bins/" + port + "/locations" );
	if(!bins){
		ssh_close_connection();
		exit( 0 );
	}
}
else {
	bins = ssh_find_file( file_name: "/(gaussdb|gsql)$", useregex: TRUE, sock: sock );
	if(!bins){
		ssh_close_connection();
		set_kb_item( name: "ssh/login/gaussdb_gsql_bins/not_found", value: TRUE );
		set_kb_item( name: "ssh/login/gaussdb_gsql_bins/" + port + "/not_found", value: TRUE );
		exit( 0 );
	}
}
found = FALSE;
found_installs = make_array();
for bin in bins {
	set_kb_item( name: "ssh/login/gaussdb_gsql_bins/found", value: TRUE );
	set_kb_item( name: "ssh/login/gaussdb_gsql_bins/" + port + "/found", value: TRUE );
	set_kb_item( name: "ssh/login/gaussdb_gsql_bins/" + port + "/locations", value: bin );
	ld_bin = bin;
	base_path = ereg_replace( string: bin, pattern: "(/s?bin/(gaussdb|gsql))$", replace: "" );
	if(!IsMatchRegexp( base_path, "/(gaussdb|gsql)$" )){
		ld_bin = "export LD_LIBRARY_PATH=\"" + base_path + "/lib\":$LD_LIBRARY_PATH; " + bin;
	}
	vers = ssh_get_bin_version( full_prog_name: ld_bin, sock: sock, version_argv: "-V", ver_pattern: "\\(openGauss ([VRCHPS0-9.]+)" );
	if(!vers || !vers[1]){
		continue;
	}
	version = vers[1];
	bin_path = ereg_replace( string: bin, pattern: "(/(gaussdb|gsql))$", replace: "" );
	if(found_installs[bin_path] && found_installs[bin_path] == version){
		continue;
	}
	found_installs[bin_path] = version;
	build = "unknown";
	if(build_match = eregmatch( pattern: "build ([^)]+)\\)", string: vers[2] )){
		build = build_match[1];
	}
	found = TRUE;
	set_kb_item( name: "huawei/opengauss/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + vers[2] + "#---#" + version + "#---#" + build );
}
if(found){
	set_kb_item( name: "huawei/opengauss/detected", value: TRUE );
	set_kb_item( name: "huawei/opengauss/port", value: port );
}
ssh_close_connection();
exit( 0 );

