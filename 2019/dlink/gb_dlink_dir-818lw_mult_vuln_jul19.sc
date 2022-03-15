if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113451" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-31 12:01:18 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 16:55:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2019-13481", "CVE-2019-13482" );
	script_bugtraq_id( 109131 );
	script_name( "D-Link DIR-818LW <= 2.06b01 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "d-link/dir/fw_version" );
	script_tag( name: "summary", value: "D-Link DIR-818LW devices are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - There is a command injection in HNAP1 (exploitable with authentication)
    via shell metacharacters in the MTU field to SetWanSettings.

  - There is a command injection in HNAP1 (exploitable with authentication)
    via shell metacharacters in the Type field to SetWantSettings." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to gain complete control over the target device." );
	script_tag( name: "affected", value: "D-Link DIR-818LW through firmware version 2.06b01." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-3.pdf" );
	script_xref( name: "URL", value: "https://github.com/TeamSeri0us/pocs/blob/master/iot/dlink/dir818-4.pdf" );
	exit( 0 );
}
CPE = "cpe:/o:d-link:dir-818lw_firmware";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.06b01" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

