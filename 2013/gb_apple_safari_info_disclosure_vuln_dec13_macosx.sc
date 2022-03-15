CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804175" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-7127" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-12-19 20:34:20 +0530 (Thu, 19 Dec 2013)" );
	script_name( "Apple Safari Information Disclosure Vulnerability Dec13 (Mac OS X)" );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to obtain sensitive
information." );
	script_tag( name: "affected", value: "Apple Safari version 6.0.5 on Mac OS X" );
	script_tag( name: "insight", value: "The flaw exists in the 'Reopen All Windows from Last Session' feature that
stores user ID and password information in the LastSession.plist file" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 6.1 or later" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "summary", value: "This host is installed with Apple Safari and is prone to information
disclosure vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/blog/8168/Loophole_in_Safari" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
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
if(version_is_equal( version: safVer, test_version: "6.0.5" )){
	report = report_fixed_ver( installed_version: safVer, vulnerable_range: "Equal to 6.0.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}

