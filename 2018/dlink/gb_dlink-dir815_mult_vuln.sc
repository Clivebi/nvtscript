CPE = "cpe:/o:d-link:dir-815_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112256" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-04-17 09:31:29 +0200 (Tue, 17 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 14:37:00 +0000 (Fri, 18 May 2018)" );
	script_cve_id( "CVE-2015-0150", "CVE-2015-0151", "CVE-2015-0152", "CVE-2015-0153" );
	script_name( "D-Link DIR-815 Rev.B < 2.07 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "d-link/dir/fw_version", "d-link/dir/hw_version" );
	script_xref( name: "URL", value: "ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-815/REVB/DIR-815_REVB_FIRMWARE_PATCH_NOTES_2.07.B01_EN.PDF" );
	script_tag( name: "summary", value: "D-Link Router DIR-815 Rev.B is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "The script checks if the target is an affected device running a vulnerable firmware version." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - The remote administration UI allows remote attackers to bypass intended access restrictions via unspecified vectors. (CVE-2015-0150)

  - Cross-site request forgery (CSRF) allows remote attackers to hijack the authentication of arbitrary users for requests that insert XSS sequences. (CVE-2015-0151)

  - It is possible for remote attackers to obtain sensitive information by leveraging cleartext storage of the administrative password or the wireless key. (CVE-2015-0152, CVE-2015-0153)" );
	script_tag( name: "affected", value: "D-Link DIR-815 Rev.B before version 2.07.B01." );
	script_tag( name: "solution", value: "Update to version 2.07.B01." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!fw_vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!hw_vers = get_kb_item( "d-link/dir/hw_version" )){
	exit( 0 );
}
hw_vers = toupper( hw_vers );
if(IsMatchRegexp( hw_vers, "^B" ) && version_is_less( version: fw_vers, test_version: "2.07" )){
	report = report_fixed_ver( installed_version: fw_vers, fixed_version: "2.07.B01", extra: "Hardware revision: " + hw_vers );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

