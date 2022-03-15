if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801524" );
	script_version( "2020-05-28T14:41:23+0000" );
	script_tag( name: "last_modification", value: "2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)" );
	script_cve_id( "CVE-2010-2883", "CVE-2010-2884", "CVE-2010-2888", "CVE-2010-2889", "CVE-2010-2890", "CVE-2010-3619", "CVE-2010-3620", "CVE-2010-3621", "CVE-2010-3622", "CVE-2010-3625", "CVE-2010-3626", "CVE-2010-3627", "CVE-2010-3628", "CVE-2010-3629", "CVE-2010-3630", "CVE-2010-3632", "CVE-2010-3656", "CVE-2010-3657", "CVE-2010-3658" );
	script_bugtraq_id( 43057, 43205, 43739, 43723, 43722, 43724, 43725, 43726, 43729, 43730, 43727, 43746, 43734, 43732, 43737, 43735, 43741, 43744, 43738 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Acrobat and Reader Multiple Vulnerabilities -Oct10 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41435/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2573" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-21.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to crash an affected application or
  execute arbitrary code by tricking a user into opening a specially crafted PDF document." );
	script_tag( name: "affected", value: "Adobe Reader version 8.x before 8.2.5 and 9.x before 9.4,

  Adobe Acrobat version 8.x before 8.2.5  and 9.x before 9.4 on Windows." );
	script_tag( name: "insight", value: "The flaws are caused by memory corruptions, array-indexing, and input validation
  errors when processing malformed data, fonts or images within a PDF document." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader/Acrobat version 9.4 or 8.2.5." );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader/Acrobat and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "8.2.5" ) || version_in_range( version: vers, test_version: "9.0", test_version2: "9.3.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.4 or 8.2.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

