CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807016" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-8459", "CVE-2015-8460", "CVE-2015-8634", "CVE-2015-8635", "CVE-2015-8636", "CVE-2015-8638", "CVE-2015-8639", "CVE-2015-8640", "CVE-2015-8641", "CVE-2015-8642", "CVE-2015-8643", "CVE-2015-8644", "CVE-2015-8645", "CVE-2015-8646", "CVE-2015-8647", "CVE-2015-8648", "CVE-2015-8649", "CVE-2015-8650", "CVE-2015-8651" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-12-29 15:41:30 +0530 (Tue, 29 Dec 2015)" );
	script_name( "Adobe Air Multiple Vulnerabilities -01 Dec15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion vulnerability.

  - An integer overflow vulnerability.

  - Multiple use-after-free vulnerabilities.

  - Multiple memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Adobe Air version before 20.0.0.233
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Air version
  20.0.0.233 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Air/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "20.0.0.233" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:  20.0.0.233 \n";
	security_message( data: report );
	exit( 0 );
}

