if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802332" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)" );
	script_cve_id( "CVE-2011-3388", "CVE-2011-3389" );
	script_bugtraq_id( 49388 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Opera Extended Validation Information Disclosure Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45791" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1025997" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1000/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to steal sensitive security
  information." );
	script_tag( name: "affected", value: "Opera version before 11.51" );
	script_tag( name: "insight", value: "Multiple flaws are due to an error when loading content from trusted
  sources in an unspecified sequence that causes the address field and page
  information dialog to contain security information based on the trusted site
  and loading an insecure site to appear secure via unspecified actions related
  to Extended Validation." );
	script_tag( name: "solution", value: "Upgrade to Opera version 11.51 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to information
  disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "11.51" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "11.51" );
	security_message( port: 0, data: report );
}

