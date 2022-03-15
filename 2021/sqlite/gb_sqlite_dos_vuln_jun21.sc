if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113819" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 09:43:10 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 23:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2019-16168" );
	script_name( "SQLite 3.8.5 - 3.29.0 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_sqlite_ssh_login_detect.sc" );
	script_mandatory_keys( "sqlite/detected" );
	script_tag( name: "summary", value: "SQLite is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "whereLoopAddBtreeIndex in sqlite3.c can crash a browser or
  another application because of missing validation of a sqlite_stat1 sz field, which can lead
  to a divide-by-zero error." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  crash the application and possibly other connected applications as well." );
	script_tag( name: "affected", value: "SQLite version 3.8.5 through 3.29.0." );
	script_tag( name: "solution", value: "No known solution is available as of 17th June, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://www.mail-archive.com/sqlite-users@mailinglists.sqlite.org/msg116312.html" );
	script_xref( name: "URL", value: "https://www.sqlite.org/src/info/e4598ecbdd18bd82945f6029013296690e719a62" );
	script_xref( name: "URL", value: "https://www.sqlite.org/src/info/b83367a95c48bf60" );
	exit( 0 );
}
CPE = "cpe:/a:sqlite:sqlite";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "3.8.5", test_version2: "3.29.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

