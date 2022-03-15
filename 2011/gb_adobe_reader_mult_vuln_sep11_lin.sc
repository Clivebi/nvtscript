CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802167" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442" );
	script_bugtraq_id( 49582, 49572, 49576, 49577, 49578, 49579, 49580, 49583, 49581, 49584, 49575, 49585 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)" );
	script_name( "Adobe Reader Multiple Vulnerabilities September-2011 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to memory corruptions, and buffer overflow errors." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code via
unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Reader version 9.x through 9.4.5" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.4.6 or later." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-24.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( readerVer, "^9" )){
	if(version_in_range( version: readerVer, test_version: "9.0", test_version2: "9.4.5" )){
		report = report_fixed_ver( installed_version: readerVer, vulnerable_range: "9.0 - 9.4.5" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

