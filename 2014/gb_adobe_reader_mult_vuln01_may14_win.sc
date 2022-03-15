CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804606" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2014-0521", "CVE-2014-0522", "CVE-2014-0523", "CVE-2014-0524", "CVE-2014-0525", "CVE-2014-0526", "CVE-2014-0527", "CVE-2014-0528", "CVE-2014-0529" );
	script_bugtraq_id( 67363, 67360, 67368, 67369, 67365, 67370, 67367, 67366, 67362 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-05-22 10:46:12 +0530 (Thu, 22 May 2014)" );
	script_name( "Adobe Reader Multiple Vulnerabilities - 01 May14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - An error within the implementation of Javascript APIs.

  - An error when validating user supplied paths.

  - An integer overflow error when handling PDF417 barcodes.

  - An error exists within the handling of certain API calls to unmapped memory.

  - A use-after-free error when handling the messageHandler property of the
AcroPDF ActiveX control.

  - A double-free error.

  - Many other unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct a denial of service,
disclose potentially sensitive information, bypass certain security
restrictions, execute arbitrary code and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Reader X before version 10.1.10 and XI before version 11.0.07 on
Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader X version 10.1.10 or XI version 11.0.07 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1030229" );
	script_xref( name: "URL", value: "https://www.hkcert.org/my_url/en/alert/14051403" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/reader/apsb14-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(vers && IsMatchRegexp( vers, "^1[01]\\." )){
	if(version_in_range( version: vers, test_version: "10.0.0", test_version2: "10.1.09" ) || version_in_range( version: vers, test_version: "11.0.0", test_version2: "11.0.06" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

