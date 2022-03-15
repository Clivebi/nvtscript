if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900957" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3275" );
	script_name( "Microsoft Windows Patterns & Practices EntLib DOS Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/506453/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.checkmarx.com/Upload/Documents/PDF/Checkmarx_OWASP_IL_2009_ReDoS.pdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_ms_wpp_enterprise_library_detect.sc" );
	script_mandatory_keys( "MS/WPP/EntLib/Ver" );
	script_tag( name: "impact", value: "Successful attack could allow attackers to crash application or CPU consumption
  and to cause denial of service." );
	script_tag( name: "affected", value: "Microsoft Windows Patterns & Practices Enterprise Library 3.1, 4.0 and 4.1." );
	script_tag( name: "insight", value: "An error occurs in Blocks/Common/Src/Configuration/Manageability/Adm/
  AdmContentBuilder.cs while processing an input string composed of many '\\' ie
  backslash characters followed by a double quote related to a certain regular
  expression." );
	script_tag( name: "solution", value: "Upgrade to Microsoft Windows Patterns & Practices Enterprise Library 5.0
  or later." );
	script_tag( name: "summary", value: "This host has Microsoft Windows Patterns & Practices Enterprise
  Library installed and is prone to Denial of Service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
entlibVer = get_kb_item( "MS/WPP/EntLib/Ver" );
if(isnull( entlibVer )){
	exit( 0 );
}
if(version_is_equal( version: entlibVer, test_version: "3.1.0.0" ) || version_is_equal( version: entlibVer, test_version: "4.0.0.0" ) || version_is_equal( version: entlibVer, test_version: "4.1.0.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

