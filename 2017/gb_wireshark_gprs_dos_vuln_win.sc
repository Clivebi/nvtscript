CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811428" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2017-11409" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-20 18:12:24 +0530 (Thu, 20 Jul 2017)" );
	script_name( "Wireshark 'GPRS' DoS Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  GPRS LLC dissector." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the affected application, resulting in denial-of-service
  conditions." );
	script_tag( name: "affected", value: "Wireshark version 2.0.0 to 2.0.13 on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 2.0.14 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2017-37.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( wirversion, "(^2\\.0)" )){
	if(version_is_less( version: wirversion, test_version: "2.0.14" )){
		report = report_fixed_ver( installed_version: wirversion, fixed_version: "2.0.14" );
		security_message( data: report );
		exit( 0 );
	}
}
