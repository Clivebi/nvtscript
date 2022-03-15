CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813373" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2018-11361", "CVE-2018-11355", "CVE-2018-11354" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-05-23 12:18:22 +0530 (Wed, 23 May 2018)" );
	script_name( "Wireshark Security Updates (wnpa-sec-2018-32_wnpa-sec-2018-27_wnpa-sec-2018-26) (MACOSX)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A buffer overflow during FTE processing in 'epan/crypt/dot11decrypt.c'
    script.

  - A buffer overflow error in 'epan/dissectors/packet-rtcp.c' script.

  - An error in string handling in 'epan/dissectors/packet-ieee1905.c' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to make Wireshark crash by injecting a malformed packet onto the wire or by
  convincing someone to read a malformed packet trace file." );
	script_tag( name: "affected", value: "Wireshark version 2.6.0 on Macosx." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.6.1 or later. Please see the references for more information." );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-32" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-27" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2018-26" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(vers == "2.6.0"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.6.1", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

