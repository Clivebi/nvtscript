CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804668" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-4174" );
	script_bugtraq_id( 66755 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-07-07 10:18:34 +0530 (Mon, 07 Jul 2014)" );
	script_name( "Wireshark 'Libpcap' Denial of Service and Code Execution Vulnerabilities (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of service and
remote code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to an unspecified error in 'wiretap/libpcap.c' within the libpcap
file parser." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a DoS (Denial of Service)
and compromise a vulnerable system." );
	script_tag( name: "affected", value: "Wireshark version 1.10.x before 1.10.4 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.10.4 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57801" );
	script_xref( name: "URL", value: "https://www.hkcert.org/my_url/en/alert/14041102" );
	script_xref( name: "URL", value: "http://www.wireshark.org/security/wnpa-sec-2014-05.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!sharkVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( sharkVer, "^(1\\.10)" )){
	if(version_in_range( version: sharkVer, test_version: "1.10.0", test_version2: "1.10.3" )){
		report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.10.0 - 1.10.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

