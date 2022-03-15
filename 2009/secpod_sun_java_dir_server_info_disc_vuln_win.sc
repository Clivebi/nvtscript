if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900497" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-1332" );
	script_bugtraq_id( 34548 );
	script_name( "Sun Java Directory Server Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34751" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-66-255848-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_sun_java_dir_server_detect_win.sc" );
	script_mandatory_keys( "Sun/JavaDirServer/Win/Ver" );
	script_tag( name: "affected", value: "Sun Java System Directory Server 5.2
  Sun Java System Directory Server Enterprise 5.0" );
	script_tag( name: "insight", value: "This flaw is due to unspecified error which can be exploited to determine
  the existence of a file on a system and disclose a single line of the file's
  content." );
	script_tag( name: "solution", value: "Upgrade to Sun Java Directory Server Enterprise 6.0 or later." );
	script_tag( name: "summary", value: "This host is running Sun Java Directory Server and is prone to Information
  Disclosure Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can gain sensitive information about the
  presence of folders and files." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
appVer = get_kb_item( "Sun/JavaDirServer/Win/Ver" );
if(!appVer){
	exit( 0 );
}
if(version_is_less_equal( version: appVer, test_version: "5.2" )){
	report = report_fixed_ver( installed_version: appVer, vulnerable_range: "Less than or equal to 5.2" );
	security_message( port: 0, data: report );
}

