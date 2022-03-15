CPE = "cpe:/a:don_ho:notepad++";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805318" );
	script_version( "$Revision: 14117 $" );
	script_cve_id( "CVE-2014-9456" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-09 13:19:25 +0530 (Fri, 09 Jan 2015)" );
	script_name( "Notepad++ Buffer overflow Vulnerability - Jan15 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_notepadpp_detect_portable_win.sc" );
	script_mandatory_keys( "Notepad++32or64/Win/installed" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35589" );
	script_xref( name: "URL", value: "http://www.security-database.com/detail.php?alert=CVE-2014-9456" );
	script_tag( name: "summary", value: "The host is installed with Notepad++
  and is prone to Buffer Overflow Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the user-supplied input
  is not properly validated when handling a specially crafted XML file." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to conduct denial of service attack or potentially allowing the
  execution of arbitrary code." );
	script_tag( name: "affected", value: "Notepad++ version 6.6.9 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Notepad++ version 6.7 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "6.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.7", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

