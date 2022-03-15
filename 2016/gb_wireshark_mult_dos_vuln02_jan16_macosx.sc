CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806946" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2015-8733", "CVE-2015-8732", "CVE-2015-8731", "CVE-2015-8730", "CVE-2015-8729", "CVE-2015-8728", "CVE-2015-8727", "CVE-2015-8726", "CVE-2015-8725", "CVE-2015-8724", "CVE-2015-8723", "CVE-2015-8722", "CVE-2015-8721", "CVE-2015-8720", "CVE-2015-8718", "CVE-2015-8711" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-07 18:29:00 +0000 (Wed, 07 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-01-11 11:59:19 +0530 (Mon, 11 Jan 2016)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-02 January16 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors in Wireshark. Please
  see the references for more information." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.9
  and 2.0.x before 2.0.1 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Wireshark version 1.12.9,
  2.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2015-45.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2015-41.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11792" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11548" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_macosx.sc" );
	script_mandatory_keys( "Wireshark/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.8" ) ){
	fix = "1.12.9";
	VULN = TRUE;
}
else {
	if(version_is_equal( version: wirversion, test_version: "2.0.0" )){
		fix = "2.0.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wirversion, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

