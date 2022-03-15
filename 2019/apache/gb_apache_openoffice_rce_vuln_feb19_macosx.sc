CPE = "cpe:/a:openoffice:openoffice.org";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814828" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_cve_id( "CVE-2018-16858" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-02-07 11:49:32 +0530 (Thu, 07 Feb 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Apache OpenOffice Remote Code Execution Vulnerability Feb19 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apache OpenOffice
  Writer and is prone to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the file 'pydoc.py' in
  LibreOffices Python interpreter which accepts and executes arbitrary commands." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and traverse directories." );
	script_tag( name: "affected", value: "Apache OpenOffice Writer through version 4.1.7." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://thehackernews.com/2019/02/hacking-libreoffice-openoffice.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openoffice_detect_macosx.sc" );
	script_mandatory_keys( "OpenOffice/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ver = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: ver, test_version: "4.1.7" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "None", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

