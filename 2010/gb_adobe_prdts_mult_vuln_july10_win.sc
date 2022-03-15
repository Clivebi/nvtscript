if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801365" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_cve_id( "CVE-2010-1285", "CVE-2010-1295", "CVE-2010-2168", "CVE-2010-2201", "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205", "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209", "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212" );
	script_bugtraq_id( 41230, 41232, 41236, 41234, 41235, 41231, 41231, 41241, 41239, 41244, 41240, 41242, 41243, 41245 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)" );
	script_name( "Adobe Acrobat and Reader Multiple Vulnerabilities -July10 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader/Acrobat and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are caused by memory corruptions, invalid pointers reference,
  uninitialized memory, array-indexing and use-after-free errors when processing
  malformed data within a PDF document." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to crash an affected application or
  execute arbitrary code by tricking a user into opening a specially crafted PDF document." );
	script_tag( name: "affected", value: "Adobe Reader version 8.x before 8.2.3 and 9.x before 9.3.3,

  Adobe Acrobat version 8.x before 8.2.3  and 9.x before 9.3.3 on windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader/Acrobat version 9.3.3 or 8.2.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://isc.incidents.org/diary.html?storyid=9100" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1636" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
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
if(version_in_range( version: vers, test_version: "8.0", test_version2: "8.2.2" ) || version_in_range( version: vers, test_version: "9.0", test_version2: "9.3.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.3.3 or 8.2.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

