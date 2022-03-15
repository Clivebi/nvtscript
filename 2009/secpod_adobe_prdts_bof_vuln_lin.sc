CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900321" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_cve_id( "CVE-2009-0658", "CVE-2009-0927" );
	script_bugtraq_id( 33751, 34169, 34229 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 16:48:00 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)" );
	script_name( "Buffer Overflow Vulnerability in Adobe Reader (Linux)" );
	script_tag( name: "summary", value: "This host has Adobe Reader installed, and is prone to buffer overflow
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This issue is due to error in array indexing while processing JBIG2 streams
and unspecified vulnerability related to a JavaScript method." );
	script_tag( name: "impact", value: "This can be exploited to corrupt arbitrary memory via a specially crafted PDF
file, related to a non-JavaScript function call and to execute arbitrary code
in context of the affected application." );
	script_tag( name: "affected", value: "Adobe Reader version 9.x < 9.1, 8.x < 8.1.4, 7.x < 7.1.1 on Linux" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.1 or 8.1.4 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33901" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb09-03.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb09-04.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa09-01.html" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/33751-PoC.pl" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Unix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( readerVer, "^[7-9]\\." )){
	if(version_in_range( version: readerVer, test_version: "7.0", test_version2: "7.1.0" ) || version_in_range( version: readerVer, test_version: "8.0", test_version2: "8.1.3" ) || IsMatchRegexp( readerVer, "^9\\.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

