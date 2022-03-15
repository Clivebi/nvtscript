if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117185" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-01-27 06:47:49 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "sudo / sudoers Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.sudo.ws/" );
	script_tag( name: "summary", value: "SSH login-based detection of sudo and various sudoers components." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
full_path_list = ssh_find_file( file_name: "/sudo$", sock: sock, useregex: TRUE );
if(!full_path_list){
	ssh_close_connection();
	exit( 0 );
}
for full_path in full_path_list {
	full_path = chomp( full_path );
	if(!full_path){
		continue;
	}
	buf = ssh_cmd( socket: sock, cmd: full_path + " -V" );
	if(!buf || !ContainsString( buf, "Sudo version " )){
		continue;
	}
	sudo_version = "unknown";
	sudo_vers_concl = "";
	set_kb_item( name: "sudo/detected", value: TRUE );
	set_kb_item( name: "sudo/ssh-login/detected", value: TRUE );
	sudo_vers = eregmatch( string: buf, pattern: "^Sudo version ([0-9.p]+)", icase: FALSE );
	if(sudo_vers[1]){
		sudo_version = sudo_vers[1];
		sudo_vers_concl = sudo_vers[0];
	}
	sudo_cpe = build_cpe( value: sudo_version, exp: "^([0-9.]+)(p[0-9]+)?", base: "cpe:/a:sudo_project:sudo:" );
	if(!sudo_cpe){
		sudo_cpe = "cpe:/a:sudo_project:sudo";
	}
	register_product( cpe: sudo_cpe, location: full_path, port: 0, service: "ssh-login" );
	report = build_detection_report( app: "Sudo", version: sudo_version, install: full_path, cpe: sudo_cpe, concluded: sudo_vers_concl );
	sudoers_comps = egrep( string: buf, pattern: "^Sudoers .+ version ", icase: FALSE );
	if(sudoers_comps){
		split_comps = split( buffer: sudoers_comps, keep: FALSE );
		for split_comp in split_comps {
			comp_info = eregmatch( string: split_comp, pattern: "(Sudoers .+) version ([0-9.p]+)", icase: FALSE );
			if(!comp_info){
				continue;
			}
			comp_concl = comp_info[0];
			comp_name = comp_info[1];
			comp_vers = comp_info[2];
			comp_base_cpe = "cpe:/a:sudo_project:" + tolower( comp_name );
			comp_base_cpe = str_replace( string: comp_base_cpe, find: " ", replace: "_" );
			comp_cpe = build_cpe( value: comp_vers, exp: "^([0-9.]+)(p[0-9]+)?", base: comp_base_cpe + ":" );
			if(!comp_cpe){
				comp_cpe = comp_base_cpe;
			}
			register_product( cpe: comp_cpe, location: full_path, port: 0, service: "ssh-login" );
			report += "\n\n";
			report += build_detection_report( app: comp_name, version: comp_vers, install: full_path, cpe: comp_cpe, concluded: comp_concl );
		}
	}
	log_message( port: 0, data: report );
}
ssh_close_connection();
exit( 0 );

