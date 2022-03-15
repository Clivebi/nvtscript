if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108577" );
	script_version( "2019-05-23T06:42:35+0000" );
	script_tag( name: "last_modification", value: "2019-05-23 06:42:35 +0000 (Thu, 23 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OpenSSH Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssh_remote_detect.sc", "gb_openssh_ssh_login_detect.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "https://www.openssh.com/" );
	script_tag( name: "summary", value: "The script reports a detected OpenSSH including the
  version number." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "openssh/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "ssh" ) {
	install_list = get_kb_list( "openssh/" + source + "/*/installs" );
	if(!install_list){
		continue;
	}
	install_list = sort( install_list );
	for install in install_list {
		infos = split( buffer: install, sep: "#---#", keep: FALSE );
		if(max_index( infos ) < 3){
			continue;
		}
		port = infos[0];
		install = infos[1];
		version = infos[2];
		concl = infos[3];
		type = infos[4];
		app_name = "OpenSSH";
		if(type){
			app_name += " " + type;
		}
		if(ContainsString( tolower( concl ), "debian" ) && !ContainsString( tolower( concl ), "ubuntu" )){
			_vers = eregmatch( pattern: "OpenSSH_([^ ]+) Debian-([^,]+)", string: concl, icase: FALSE );
			if(_vers[1] && _vers[2]){
				set_kb_item( name: "openssh/" + port + "/debian_version", value: _vers[1] + "-" + _vers[2] );
			}
		}
		cpe = build_cpe( value: version, exp: "^([.a-zA-Z0-9]+)", base: "cpe:/a:openbsd:openssh:" );
		if(!cpe){
			cpe = "cpe:/a:openbsd:openssh";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: app_name, version: version, install: install, cpe: cpe, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

