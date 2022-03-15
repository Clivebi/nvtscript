CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804382" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2007-1199" );
	script_bugtraq_id( 22753 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-04-10 12:02:02 +0530 (Thu, 10 Apr 2014)" );
	script_name( "Adobe Reader 'file://' URL Information Disclosure Vulnerability Feb07 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to information disclosure
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to some unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain sensitive information." );
	script_tag( name: "affected", value: "Adobe Reader version 8 and prior on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 8.1.2 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/24408" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/32815" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_prdts_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Reader/Linux/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "8.0" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 8.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

