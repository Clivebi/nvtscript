CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804257" );
	script_version( "2021-08-13T07:21:38+0000" );
	script_cve_id( "CVE-2005-2470" );
	script_bugtraq_id( 14603 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 07:21:38 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-15 18:57:59 +0530 (Tue, 15 Apr 2014)" );
	script_name( "Adobe Reader 'Plug-in' Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to an unspecified boundary error in the core application
plug-in." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct denial of service and
possibly execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Reader version 5.1, 6.x through 6.0.3, 7.x through 7.0.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader 6.0.4 or 7.0.5 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/16466" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1014712" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/techdocs/321644.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "5.1" ) || version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.2" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

