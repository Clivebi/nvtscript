if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112690" );
	script_version( "2020-10-27T06:35:27+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 06:35:27 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-01-15 14:52:00 +0000 (Wed, 15 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Huawei GaussDB Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_huawei_gaussdb_ssh_login_detect.sc" );
	script_mandatory_keys( "huawei/gaussdb/detected" );
	script_xref( name: "URL", value: "https://e.huawei.com/en/solutions/cloud-computing/big-data/gaussdb-distributed-database" );
	script_tag( name: "summary", value: "Consolidation of Huawei GaussDB detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "huawei/gaussdb/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login" ) {
	install_list = get_kb_list( "huawei/gaussdb/" + source + "/*/installs" );
	if(!install_list){
		continue;
	}
	install_list = sort( install_list );
	for install in install_list {
		infos = split( buffer: install, sep: "#---#", keep: FALSE );
		port = infos[0];
		install = infos[1];
		concl = infos[2];
		version = infos[3];
		type = infos[4];
		model = infos[5];
		build = infos[6];
		release = infos[7];
		extra = "";
		if( type != "unknown" ){
			if( IsMatchRegexp( type, "^100" ) ){
				app_name = "GaussDB 100 OLTP";
				cpe_suffix = "gaussdb_100_oltp";
			}
			else {
				if( IsMatchRegexp( type, "^200" ) ){
					app_name = "GaussDB 200 OLAP";
					cpe_suffix = "gaussdb_200_olap";
				}
				else {
					if( IsMatchRegexp( type, "^300" ) ){
						app_name = "GaussDB 300";
						cpe_suffix = "gaussdb_300";
					}
					else {
						app_name = "GaussDB " + type;
						cpe_suffix = "gaussdb_" + tolower( type );
					}
				}
			}
		}
		else {
			app_name = "GaussDB (Unknown Type)";
			cpe_suffix = "gaussdb_unknown_type";
		}
		if(model != "unknown"){
			app_name = model + app_name;
		}
		cpe = build_cpe( value: tolower( version ), exp: "^([a-z0-9.]+)", base: "cpe:/a:huawei:" + cpe_suffix + ":" );
		if(!cpe){
			cpe = "cpe:/a:huawei:" + cpe_suffix;
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		register_product( cpe: "cpe:/a:huawei:gaussdb", location: install, port: port, service: source );
		if(build != "unknown" && strlen( build ) == 3){
			extra += "Internal build " + build;
		}
		if(release != "unknown"){
			if( !isnull( extra ) ) {
				extra += "\n" + release;
			}
			else {
				extra += release;
			}
		}
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Huawei " + app_name, version: version, install: install, cpe: cpe, concluded: concl, extra: extra );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

