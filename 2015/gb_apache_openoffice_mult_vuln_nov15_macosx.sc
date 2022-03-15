CPE = "cpe:/a:openoffice:openoffice.org";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806702" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-5214", "CVE-2015-5213", "CVE-2015-5212", "CVE-2015-4551" );
	script_bugtraq_id( 77486 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-16 18:28:06 +0530 (Mon, 16 Nov 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Apache OpenOffice Multiple Vulnerabilities Nov15 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Apache
  OpenOffice and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Usage of stored LinkUpdateMode configuration information in OpenDocument
    Format files and templates when handling links.

  - Integer underflow when the configuration setting 'Load printer settings with
    the document' is enabled.

  - Integer overflow via a long DOC file.

  - Incorrect handling of bookmarks in DOC files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information, cause a denial of service or
  possibly execute arbitrary code." );
	script_tag( name: "affected", value: "Apache OpenOffice version before 4.1.2 on
  Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Apache OpenOffice version
  4.1.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.openoffice.org/security/cves/CVE-2015-5214.html" );
	script_xref( name: "URL", value: "http://www.openoffice.org/security/cves/CVE-2015-5213.html" );
	script_xref( name: "URL", value: "http://www.openoffice.org/security/cves/CVE-2015-5212.html" );
	script_xref( name: "URL", value: "http://www.openoffice.org/security/cves/CVE-2015-4551.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_openoffice_detect_macosx.sc" );
	script_mandatory_keys( "OpenOffice/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!openoffcVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: openoffcVer, test_version: "4.1.2" )){
	report = "Installed version: " + openoffcVer + "\n" + "Fixed version:     4.1.2\n";
	security_message( data: report );
	exit( 0 );
}

