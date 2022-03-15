CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804814" );
	script_version( "2019-07-05T08:56:43+0000" );
	script_cve_id( "CVE-2014-0546" );
	script_bugtraq_id( 69193 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 08:56:43 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-08-19 12:25:49 +0530 (Tue, 19 Aug 2014)" );
	script_name( "Adobe Acrobat Sandbox Bypass Vulnerability - Aug14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat and is prone to sandbox bypass
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to some unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass sandbox restrictions
and execute native code in a privileged context." );
	script_tag( name: "affected", value: "Adobe Acrobat X version 10.x before 10.1.11 and XI version 11.x before 11.0.08
on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 10.1.11 or 11.0.08 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/reader/apsb14-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!acrobatVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(acrobatVer && IsMatchRegexp( acrobatVer, "^(10|11)" )){
	if(( version_in_range( version: acrobatVer, test_version: "10.0", test_version2: "10.1.10" ) ) || ( version_in_range( version: acrobatVer, test_version: "11.0", test_version2: "11.0.07" ) )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

