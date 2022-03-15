CPE = "cpe:/a:zohocorp:manageengine_admanager_plus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107128" );
	script_version( "2021-09-27T14:27:18+0000" );
	script_tag( name: "last_modification", value: "2021-09-27 14:27:18 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ManageEngine ADManager Plus < 6.5 build 6541 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manageengine_admanager_plus_consolidation.sc" );
	script_mandatory_keys( "manageengine/admanager_plus/detected" );
	script_tag( name: "summary", value: "ManageEngine ADManager Plus is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Exploitation of these vulnerabilities could allow a remote
  attacker to execute arbitrary HTML and script code in a user's browser session in context of an
  affected site." );
	script_tag( name: "affected", value: "ManageEngine ADManager Plus version 6.5 build 6540 and prior." );
	script_tag( name: "solution", value: "Update to version 6.5 build 6541 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/41082/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
ver = infos["version"];
path = infos["location"];
vers = eregmatch( pattern: "([0-9]+\\.[0-9])([0-9]+)", string: ver );
if(!isnull( vers[1] )){
	rep_vers = vers[1];
	build = vers[2];
}
if(version_is_less_equal( version: ver, test_version: "6.56540" )){
	report = report_fixed_ver( installed_version: rep_vers, installed_build: build, fixed_version: "6.5", fixed_build: "6541", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

