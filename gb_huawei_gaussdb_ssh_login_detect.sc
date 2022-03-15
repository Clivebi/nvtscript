if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112689" );
	script_version( "2021-07-20T06:19:26+0000" );
	script_tag( name: "last_modification", value: "2021-07-20 06:19:26 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-01-15 09:53:11 +0000 (Wed, 15 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Huawei GaussDB Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Huawei GaussDB." );
	script_xref( name: "URL", value: "https://e.huawei.com/en/solutions/cloud-computing/big-data/gaussdb-distributed-database" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
bins = ssh_find_file( file_name: "/(zengine|zsql)$", useregex: TRUE, sock: sock );
if(!bins){
	ssh_close_connection();
	exit( 0 );
}
found = FALSE;
found_installs = make_array();
ver_pattern = "^(Zenith-)?Gauss(DB[-_])?([0-9A-Z]+)[-_]([A-Z]+[-_])?([A-Z0-9.]+) ?(Release [0-9a-z]+)?";
for bin in bins {
	ld_bin = bin;
	base_path = ereg_replace( string: bin, pattern: "(/s?bin/(zengine|zsql))$", replace: "" );
	if(!IsMatchRegexp( base_path, "/(zengine|zsql)$" )){
		ld_bin = "export LD_LIBRARY_PATH=\"" + base_path + "/lib\":\"" + base_path + "/add-ons\":$LD_LIBRARY_PATH; " + bin;
	}
	vers = ssh_get_bin_version( full_prog_name: ld_bin, sock: sock, version_argv: "-v", ver_pattern: ver_pattern );
	if(!vers){
		continue;
	}
	vers = eregmatch( pattern: ver_pattern, string: vers[0] );
	if(!isnull( vers[5] )){
		version = vers[5];
		bin_path = ereg_replace( string: bin, pattern: "(/(zengine|zsql))$", replace: "" );
		if(found_installs[bin_path] && found_installs[bin_path] == version){
			continue;
		}
		type = "unknown";
		model = "unknown";
		build = "unknown";
		release = "unknown";
		found_installs[bin_path] = version;
		if(!isnull( vers[3] )){
			type = vers[3];
		}
		if(!isnull( vers[1] )){
			model = vers[1];
		}
		if(build_match = eregmatch( pattern: "\\.?B([0-9]{3})$", string: version )){
			version = ereg_replace( pattern: build_match[0], string: version, replace: "" );
			build = build_match[1];
		}
		if(!isnull( vers[6] )){
			release = vers[6];
		}
		found = TRUE;
		set_kb_item( name: "huawei/gaussdb/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + vers[0] + "#---#" + version + "#---#" + type + "#---#" + model + "#---#" + build + "#---#" + release );
	}
}
if(found){
	set_kb_item( name: "huawei/gaussdb/detected", value: TRUE );
	set_kb_item( name: "huawei/gaussdb/port", value: port );
}
ssh_close_connection();
exit( 0 );

