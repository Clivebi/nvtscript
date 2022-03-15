CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814191" );
	script_version( "2021-06-01T06:00:14+0200" );
	script_cve_id( "CVE-2018-15979" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-01 06:00:14 +0200 (Tue, 01 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-21 16:20:00 +0000 (Wed, 21 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-11-15 12:20:16 +0530 (Thu, 15 Nov 2018)" );
	script_name( "Adobe Reader DC Information Disclosure Vulnerability (apsb18-40) - Mac OS X" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader DC
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in handing
  the feature of Portable Document Files (PDFs).That leaks NT LAN Manager (NTLM)
  credentials." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inadvertent leak of the users hashed NTLM password." );
	script_tag( name: "affected", value: "Adobe Reader DC version 2019.x before 2019.008.20081 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader DC version
  2019.008.20081 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/acrobat/apsb18-40.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_acrobat_reader_dc_cont_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Acrobat/ReaderDC/Continuous/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "2019.0", test_version2: "2019.008.20080" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "19.008.20081 (2019.008.20081)", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

