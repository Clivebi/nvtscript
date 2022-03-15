CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806608" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-5928", "CVE-2015-5929", "CVE-2015-5930", "CVE-2015-5931", "CVE-2015-7002", "CVE-2015-7011", "CVE-2015-7012", "CVE-2015-7013", "CVE-2015-7014" );
	script_bugtraq_id( 77264, 77267 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-11-03 14:39:29 +0530 (Tue, 03 Nov 2015)" );
	script_name( "Apple Safari Multiple Vulnerabilities-01 Nov15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  memory corruption issues in webKit." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Apple Safari versions before 9.0.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 9.0.1 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT205377" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2015/Oct/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!safVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: safVer, test_version: "9.0.1" )){
	report = "Installed version: " + safVer + "\n" + "Fixed version:     " + "9.0.1" + "\n";
	security_message( data: report );
	exit( 0 );
}

