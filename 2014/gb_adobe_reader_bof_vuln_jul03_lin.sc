CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804628" );
	script_version( "$Revision: 11402 $" );
	script_cve_id( "CVE-2003-0508" );
	script_bugtraq_id( 8069 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-05 11:29:17 +0530 (Thu, 05 Jun 2014)" );
	script_name( "Adobe Reader 'WWWLaunchNetscape' Buffer Overflow Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error in the 'WWWLaunchNetscape' function in the
file wwwlink.api." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Reader version 5.0.5, 5.0.6, 5.0.7 and probably other versions on
Linux." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/12479" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( readerVer, "^5\\." )){
	if(version_in_range( version: readerVer, test_version: "5.0.5", test_version2: "5.0.7" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

