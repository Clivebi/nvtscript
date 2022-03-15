CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804486" );
	script_version( "2021-08-11T09:52:19+0000" );
	script_cve_id( "CVE-2014-0560", "CVE-2014-0561", "CVE-2014-0563", "CVE-2014-0565", "CVE-2014-0566", "CVE-2014-0567", "CVE-2014-0568" );
	script_bugtraq_id( 69823, 69821, 69826, 69824, 69825, 69827, 69828 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 09:52:19 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-19 13:51:49 +0530 (Fri, 19 Sep 2014)" );
	script_name( "Adobe Acrobat Multiple Vulnerabilities-01 Sep14 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An use-after-free error can be exploited to execute arbitrary code.

  - An unspecified error can be exploited to conduct cross-site scripting
    attacks.

  - An error within the implementation of the 'replace()' JavaScript function
    can be exploited to cause a heap-based buffer overflow via specially crafted
    arguments.

  - An error within the 3DIF Plugin (3difr.x3d) can be exploited to cause
    a heap-based buffer overflow via a specially crafted PDF file.

  - Some unspecified errors can be exploited to cause a memory corruption.

  - An unspecified error can be exploited to bypass certain sandbox
    restrictions." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to disclose potentially sensitive information, bypass certain
  security restrictions, execute arbitrary code and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Acrobat 10.x before 10.1.12 and
  11.x before 11.0.09 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat version 10.1.12 or
  11.0.09 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/60901" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/reader/apsb14-20.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!acroVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(acroVer && IsMatchRegexp( acroVer, "^(10|11)" )){
	if(version_in_range( version: acroVer, test_version: "10.0.0", test_version2: "10.1.11" ) || version_in_range( version: acroVer, test_version: "11.0.0", test_version2: "11.0.08" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

