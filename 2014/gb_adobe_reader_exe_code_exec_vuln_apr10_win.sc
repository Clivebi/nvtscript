CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804367" );
	script_version( "$Revision: 11402 $" );
	script_cve_id( "CVE-2009-4764" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-04-08 14:57:04 +0530 (Tue, 08 Apr 2014)" );
	script_name( "Adobe Reader EXE Code Execution Vulnerability Apr10 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to exe code execution
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to some unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to possibly execute arbitrary
code and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Reader 8.x through 8.1.7 and 9.x through 9.3 on Windows." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/57994" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/392605.php" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(readerVer && IsMatchRegexp( readerVer, "^(8|9)" )){
	if(version_in_range( version: readerVer, test_version: "8.0", test_version2: "8.1.7" ) || version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

