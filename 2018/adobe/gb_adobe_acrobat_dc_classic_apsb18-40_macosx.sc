CPE = "cpe:/a:adobe:acrobat_dc_classic";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814193" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-15979" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-11-15 12:20:33 +0530 (Thu, 15 Nov 2018)" );
	script_name( "Adobe Acrobat DC 2015 Information Disclosure Vulnerability (apsb18-40) - Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat DC 2015
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in handing
  the feature of Portable Document Files (PDFs).That leaks NT LAN Manager (NTLM)
  credentials." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to an inadvertent leak of the users hashed NTLM password." );
	script_tag( name: "affected", value: "Adobe Acrobat DC 2015 version 2015.x before 2015.006.30457 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat DC 2015 version
  2015.006.30457 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb18-40.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_dc_classic_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/AcrobatDC/Classic/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "2015.0", test_version2: "2015.006.30456" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "15.006.30457 (2015.006.30457)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

