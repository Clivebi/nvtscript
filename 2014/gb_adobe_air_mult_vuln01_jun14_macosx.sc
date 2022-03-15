CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804649" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-0531", "CVE-2014-0532", "CVE-2014-0533", "CVE-2014-0534", "CVE-2014-0535", "CVE-2014-0536" );
	script_bugtraq_id( 67962, 67973, 67974, 67963, 67970, 67961 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-06-19 14:42:27 +0530 (Thu, 19 Jun 2014)" );
	script_name( "Adobe AIR Multiple Vulnerabilities-01 Jun14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Certain unspecified input is not properly sanitised before being returned to
the user.

  - An unspecified error can be exploited to bypass certain security restrictions.

  - Another unspecified error can be exploited to corrupt memory.

  - Another unspecified error can be exploited to bypass certain security
restrictions." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe AIR before version 14.0.0.110 on Mac OS X." );
	script_tag( name: "solution", value: "Update to Adobe AIR version 14.0.0.110 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb14-16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Air/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "14.0.0.110" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "14.0.0.110" );
	security_message( port: 0, data: report );
	exit( 0 );
}

