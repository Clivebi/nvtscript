CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812325" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-7844" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-06 17:42:00 +0000 (Mon, 06 Aug 2018)" );
	script_tag( name: "creation_date", value: "2017-12-05 13:09:19 +0530 (Tue, 05 Dec 2017)" );
	script_name( "Mozilla Firefox Information Disclosure Vulnerability(mfsa_2017-27)-Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as visited history
  information leak through SVG image." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Mozilla Firefox version 57 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 57.0.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-27" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(ffVer == "57.0"){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "57.0.1", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

