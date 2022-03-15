CPE = "cpe:/o:d-link:dir-815_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112258" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-04-17 10:05:29 +0200 (Tue, 17 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 13:59:00 +0000 (Fri, 18 May 2018)" );
	script_cve_id( "CVE-2018-10106", "CVE-2018-10107", "CVE-2018-10108" );
	script_name( "D-Link DIR-815 Rev.B <= 2.07.B01 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_mandatory_keys( "d-link/dir/fw_version", "d-link/dir/hw_version" );
	script_xref( name: "URL", value: "https://github.com/iceMatcha/Some-Vulnerabilities-of-D-link-Dir815/blob/master/Vulnerabilities_Summary.md" );
	script_tag( name: "summary", value: "D-Link Router DIR-815 Rev.B is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "The script checks if the target is an affected device running a vulnerable
  firmware version." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - It is possible for a remote attacker to bypass access restrictions and obtain important information.
    (CVE-2018-10106)

  - An attacker can use the XSS to target which is an authenticated user in order to steal the authentication
    cookies. (CVE-2018-10107, CVE-2018-10108)" );
	script_tag( name: "affected", value: "D-Link DIR-815 Rev.B up to and including version 2.07.B01." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this
  vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable
  respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
if(IsMatchRegexp( hw_vers, "^B" ) && version_is_less_equal( version: fw_vers, test_version: "2.07" )){
	report = report_fixed_ver( installed_version: fw_vers, fixed_version: "None Available", extra: "Hardware revision: " + hw_vers );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

