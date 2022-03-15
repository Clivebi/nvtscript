if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113691" );
	script_version( "2020-08-25T05:50:37+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 05:50:37 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-05-18 14:37:30 +0200 (Mon, 18 May 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "FTPDMIN End Of Life Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ftpdmin_detect.sc" );
	script_mandatory_keys( "ftpdmin/installed" );
	script_tag( name: "summary", value: "The FTPDMIN version on the remote host has reached the end of life and should not be used anymore." );
	script_tag( name: "impact", value: "FTPDMIN is not receiving any  security updates from the vendor.
  Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host." );
	script_tag( name: "solution", value: "Uninstall FTPDMIN and change to a different FTP Server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
CPE = "cpe:/a:ftpdmin:ftpdmin";
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "FTPDMIN", cpe: CPE, version: version, location: location, eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

