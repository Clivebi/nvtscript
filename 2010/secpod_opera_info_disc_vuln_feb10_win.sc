if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902122" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0653" );
	script_name( "Opera Information Disclosure Vulnerability - (Windows)" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/390938.php" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=9877" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain sensitive
information via a crafted document." );
	script_tag( name: "affected", value: "Opera version prior to 10.10 on Windows." );
	script_tag( name: "insight", value: "- Opera permits cross-origin loading of CSS stylesheets even when the
stylesheet download has an incorrect MIME type and the stylesheet document
is malformed." );
	script_tag( name: "solution", value: "Upgrade to Opera version 10.10." );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to
Information Disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "10.10" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "10.10" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

