CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809879" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5390", "CVE-2017-5396", "CVE-2017-5383", "CVE-2017-5373" );
	script_bugtraq_id( 95757, 95758, 95769, 95762 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-02 19:35:00 +0000 (Thu, 02 Aug 2018)" );
	script_tag( name: "creation_date", value: "2017-01-27 12:15:21 +0530 (Fri, 27 Jan 2017)" );
	script_name( "Mozilla Thunderbird Security Updates(mfsa_2017-03_2017-03)-Windows" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Excessive JIT code allocation allows bypass of ASLR and DEP.

  - Use-after-free in XSL.

  - Pointer and frame data leakage of Javascript objects.

  - Potential use-after-free during DOM manipulations.

  - Insecure communication methods in Developer Tools JSON viewer.

  - Use-after-free with Media Decoder.

  - Location bar spoofing with unicode characters.

  - Memory safety bugs fixed in Thunderbird 45.7." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before
  45.7 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 45.7." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-03/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "45.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "45.7" );
	security_message( data: report );
	exit( 0 );
}

