CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804631" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2006-3452" );
	script_bugtraq_id( 18945 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-06-05 12:48:53 +0530 (Thu, 05 Jun 2014)" );
	script_name( "Adobe Reader Privilege Escalation Vulnerability - Jul07 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to privilege escalation
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insecure default file permissions being set on the
installed files and folders." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain elevated privileges and
remove the files or replace them with malicious binaries." );
	script_tag( name: "affected", value: "Adobe Reader version 6.0.4 and before on Mac OS X." );
	script_tag( name: "solution", value: "Update to Adobe Reader version 6.0.5 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1016473" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/27678" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb06-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Reader/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: readerVer, test_version: "6.0.4" )){
	report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "Less than or equal to 6.0.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}

