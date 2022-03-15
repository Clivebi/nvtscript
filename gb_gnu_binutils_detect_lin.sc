if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806085" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 15:03:47 +0530 (Tue, 13 Oct 2015)" );
	script_name( "GNU Binutils Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_gnu_assembler_detect_lin.sc" );
	script_mandatory_keys( "gnu/binutils/binaries/detected" );
	script_tag( name: "summary", value: "Detects the installed version of GNU Binutils.

  The script tries to enumerate the installed Binutils version(s) from various previously
  found binaries included in this suite." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
info_list = get_kb_list( "gnu/binutils/binaries/list" );
if(!info_list){
	exit( 0 );
}
dup_ver_list = make_list();
for info in info_list {
	split = split( buffer: info, sep: "#----#", keep: FALSE );
	if(!split || max_index( split ) != 3){
		continue;
	}
	version = split[1];
	if(!IsMatchRegexp( version, "^[0-9.]{3,}" ) || in_array( search: version, array: dup_ver_list, part_match: FALSE )){
		continue;
	}
	dup_ver_list = make_list( dup_ver_list,
		 version );
	binary_name = split[0];
	concluded = split[2];
	set_kb_item( name: "gnu/binutils/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:gnu:binutils:" );
	if(!cpe){
		cpe = "cpe:/a:gnu:binutils";
	}
	register_product( cpe: cpe, location: binary_name, port: 0, service: "ssh-login" );
	log_message( data: build_detection_report( app: "GNU Binutils", version: version, install: binary_name, cpe: cpe, concluded: concluded ), port: 0 );
}
exit( 0 );

