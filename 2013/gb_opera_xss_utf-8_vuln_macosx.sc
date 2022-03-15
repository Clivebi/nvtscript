CPE = "cpe:/a:opera:opera_browser";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804103" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-4705" );
	script_bugtraq_id( 31795 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-10-01 17:28:40 +0530 (Tue, 01 Oct 2013)" );
	script_name( "Opera Cross-Site Scripting (XSS) Vulnerability (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Opera and is prone to XSS attack." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Opera version 15.00 or later." );
	script_tag( name: "insight", value: "The flaw is due to some error when encoding settings are set to UTF-8." );
	script_tag( name: "affected", value: "Opera versions prior to 15.00 on Mac OS X." );
	script_tag( name: "impact", value: "Successful exploitation will let attacker to execute an arbitrary web
script or HTML on the user's web browser." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN01094166/index.html" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/jvndb/JVNDB-2013-000086" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/unified/1500" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_macosx.sc" );
	script_mandatory_keys( "Opera/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!operaVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "15.0" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "15.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

