CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807607" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963", "CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989", "CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0992", "CVE-2016-0993", "CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-0997", "CVE-2016-0998", "CVE-2016-0999", "CVE-2016-1000", "CVE-2016-1001", "CVE-2016-1002", "CVE-2016-1005", "CVE-2016-1010" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-11 13:53:32 +0530 (Fri, 11 Mar 2016)" );
	script_name( "Adobe Flash Player Security Updates-APSB16-08 (MAC OS X)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An integer overflow vulnerabilities.

  - A use-after-free vulnerabilities.

  - A heap overflow vulnerability.

  - The memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player version before
  18.0.0.333 and 19.x and 20.x before 21.0.0.182 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version
  18.0.0.333, or 21.0.0.182, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( version_in_range( version: playerVer, test_version: "19.0", test_version2: "21.0.0.181" ) ){
	fix = "21.0.0.182";
	VULN = TRUE;
}
else {
	if(version_is_less( version: playerVer, test_version: "18.0.0.333" )){
		fix = "18.0.0.333";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

