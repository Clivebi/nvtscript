if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801728" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)" );
	script_cve_id( "CVE-2011-0450", "CVE-2011-0682", "CVE-2011-0681", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0687", "CVE-2011-0686" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Opera Browser Multiple Vulnerabilities Feb-11 (Windows)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/985/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1101/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service." );
	script_tag( name: "affected", value: "Opera Web Browser Version prior 11.01" );
	script_tag( name: "insight", value: "Multiple flaws are caused due to:

  - An error in determining the pathname of the filesystem-viewing application

  - An error in handling large form inputs

  - An error Cascading Style Sheets (CSS) Extensions for XML implementation

  - An error while restricting the use of opera: URLs

  - An error in handling of redirections and unspecified other HTTP responses

  - An error in implementing the 'Clear all email account passwords' option,
    which might allow physically proximate attackers to access an e-mail
    account via an unattended workstation

  - An error in the implementation of Wireless Application Protocol (WAP)
    dropdown lists." );
	script_tag( name: "solution", value: "Upgrade to Opera Web Browser Version 11.01 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Opera browser and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(operaVer){
	if(version_is_less( version: operaVer, test_version: "11.01" )){
		report = report_fixed_ver( installed_version: operaVer, fixed_version: "11.01" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

