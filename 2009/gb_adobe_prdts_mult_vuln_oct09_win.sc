if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800957" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_cve_id( "CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981", "CVE-2009-2982", "CVE-2009-2983", "CVE-2009-2984", "CVE-2009-2985", "CVE-2009-2986", "CVE-2009-2987", "CVE-2009-2988", "CVE-2009-2989", "CVE-2009-2990", "CVE-2009-2991", "CVE-2009-2992", "CVE-2009-2993", "CVE-2009-2994", "CVE-2009-2995", "CVE-2009-2996", "CVE-2009-2997", "CVE-2009-2998", "CVE-2009-3458", "CVE-2009-3459", "CVE-2009-3460", "CVE-2009-3431" );
	script_bugtraq_id( 36686, 36687, 36688, 36691, 36667, 36690, 36680, 36682, 36693, 36665, 36669, 36689, 36694, 36681, 36671, 36678, 36677, 36600, 36638, 35148 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)" );
	script_name( "Adobe Reader/Acrobat Multiple Vulnerabilities - Oct09 (Windows)" );
	script_tag( name: "summary", value: "This host has Adobe Reader/Acrobat installed which is/are prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "For more information about the vulnerabilities, refer to the links mentioned
  below." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code,
  write arbitrary files or folders to the filesystem, escalate local privileges,
  or cause a denial of service on an affected system by tricking the user to
  open a malicious PDF document." );
	script_tag( name: "affected", value: "Adobe Reader and Acrobat version 7.x before 7.1.4, 8.x before 8.1.7 and 9.x
  before 9.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat and Reader versions 9.2, 8.1.7, or 7.1.4 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36983" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53691" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2851" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2898" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Oct/1023007.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb09-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:acrobat_reader",
	 "cpe:/a:adobe:acrobat" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.1.3" ) || version_in_range( version: vers, test_version: "8.0", test_version2: "8.1.6" ) || version_in_range( version: vers, test_version: "9.0", test_version2: "9.1.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.2, 8.1.7, or 7.1.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

