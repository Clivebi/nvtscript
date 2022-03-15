CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804898" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-8710" );
	script_bugtraq_id( 71069 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-11-28 12:12:22 +0530 (Fri, 28 Nov 2014)" );
	script_name( "Wireshark Denial-of-Service Vulnerability-02 Nov14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to a buffer overflow error
  within the SigComp dissector." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.10.x before 1.10.11
  on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to version 1.10.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62367" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2014-20.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "1.10.0", test_version2: "1.10.10" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "1.10.0 - 1.10.10" );
	security_message( port: 0, data: report );
	exit( 0 );
}

