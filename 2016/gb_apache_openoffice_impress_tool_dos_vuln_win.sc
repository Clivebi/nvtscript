CPE = "cpe:/a:openoffice:openoffice.org";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808653" );
	script_version( "$Revision: 12455 $" );
	script_cve_id( "CVE-2016-1513" );
	script_bugtraq_id( 92079 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-16 14:06:15 +0530 (Tue, 16 Aug 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Apache OpenOffice 'Impress Tool' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Apache
  OpenOffice and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an OpenDocument
  Presentation .ODP or Presentation Template .OTP file can contain invalid
  presentation elements that lead to memory corruption when the document is
  loaded in Apache OpenOffice Impress." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to cause denial of service and possible execution of
  arbitrary code." );
	script_tag( name: "affected", value: "Apache OpenOffice before 4.1.2 and
  earlier on Windows." );
	script_tag( name: "solution", value: "As a workaround it is recommended
  to consider the actions suggested in the referenced links." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "https://bz.apache.org/ooo/show_bug.cgi?id=127045" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0051" );
	script_xref( name: "URL", value: "http://www.openoffice.org/security/cves/CVE-2016-1513.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_openoffice_detect_win.sc" );
	script_mandatory_keys( "OpenOffice/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!openoffcVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: openoffcVer, test_version: "4.12.9782" )){
	report = report_fixed_ver( installed_version: openoffcVer, fixed_version: "Apply the Workaround" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

