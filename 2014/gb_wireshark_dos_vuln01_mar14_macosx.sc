CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804334" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2014-2282" );
	script_bugtraq_id( 66070 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-03-14 11:40:29 +0530 (Fri, 14 Mar 2014)" );
	script_name( "Wireshark 'M3UA' Denial of Service Vulnerability-01 Mar14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark and is prone to denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to improper memory allocation by 'dissect_protocol_data_parameter'
  function within the M3UA dissector (epan/dissectors/packet-m3ua.c)." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a Denial of Service." );
	script_tag( name: "affected", value: "Wireshark version 1.10.x before 1.10.6 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.10.6 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57265" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
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
	if(version_in_range( version: sharkVer, test_version: "1.10.0", test_version2: "1.10.5" )){
		report = report_fixed_ver( installed_version: sharkVer, vulnerable_range: "1.10.0 - 1.10.5" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

