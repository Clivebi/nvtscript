CPE = "cpe:/a:libreoffice:libreoffice";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806700" );
	script_version( "2019-07-05T10:16:38+0000" );
	script_cve_id( "CVE-2015-5214" );
	script_bugtraq_id( 77486 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 10:16:38 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-11-16 18:04:19 +0530 (Mon, 16 Nov 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "LibreOffice DOC Bookmarks Denial of Service Vulnerability Nov15 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with LibreOffice
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of
  bookmarks in DOC files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause denial of service (memory corruption and application crash)
  and possible execution of arbitrary code." );
	script_tag( name: "affected", value: "LibreOffice version before 4.4.6 and
  5.x before 5.0.1 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to LibreOffice version
  4.4.6 or 5.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.libreoffice.org/about-us/security/advisories/cve-2015-5214" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_libreoffice_detect_macosx.sc" );
	script_mandatory_keys( "LibreOffice/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!libreVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: libreVer, test_version: "4.4.6" )){
	fix = "4.4.6";
	VULN = TRUE;
}
if(IsMatchRegexp( libreVer, "^5" )){
	if(version_is_less( version: libreVer, test_version: "5.0.1" )){
		fix = "5.0.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = "Installed version: " + libreVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

