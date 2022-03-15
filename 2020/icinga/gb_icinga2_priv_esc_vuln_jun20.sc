if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113702" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-15 07:30:28 +0000 (Mon, 15 Jun 2020)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-03 07:15:00 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-14004" );
	script_name( "Icinga 2 < 2.12.0-rc1 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_icinga2_detect.sc" );
	script_mandatory_keys( "icinga2/detected" );
	script_tag( name: "summary", value: "Icinga 2 is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "If /run/icinga2/cmd is a symlink, then it will be followed and
  arbitrary files can be changed to mode 2750 by the unprivileged icinga2 user." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  read sensitive information or gain elevated privileges." );
	script_tag( name: "affected", value: "Icinga 2 through version 2.11.3." );
	script_tag( name: "solution", value: "Update to version 2.12.0-rc1 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2020/06/12/1" );
	exit( 0 );
}
CPE = "cpe:/a:icinga:icinga2";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.12.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.12.0", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

