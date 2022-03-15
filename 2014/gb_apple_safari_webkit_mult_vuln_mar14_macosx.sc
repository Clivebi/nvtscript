CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804319" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-1268", "CVE-2014-1269", "CVE-2014-1270" );
	script_bugtraq_id( 65778, 65780, 65781 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-03-03 16:56:35 +0530 (Mon, 03 Mar 2014)" );
	script_name( "Apple Safari 'Webkit' Multiple Vulnerabilities-01 Mar14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist in Apple Safari WebKit due to improper handling of
memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct arbitrary code
execution or denial of service." );
	script_tag( name: "affected", value: "Apple Safari before version 6.1.2 and 7.x before version 7.0.2 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 6.1.2 or 7.0.2 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6145" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57093" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125428/Apple-Security-Advisory-2014-02-25-2.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!safVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: safVer, test_version: "6.1.2" ) || version_in_range( version: safVer, test_version: "7.0", test_version2: "7.0.1" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

