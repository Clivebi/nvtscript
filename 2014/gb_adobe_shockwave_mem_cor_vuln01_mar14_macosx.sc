CPE = "cpe:/a:adobe:shockwave_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804518" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-0505" );
	script_bugtraq_id( 66182 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-03-21 14:15:03 +0530 (Fri, 21 Mar 2014)" );
	script_name( "Adobe Shockwave Player Memory Corruption Vulnerability Mar14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave Player and is prone to memory
corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws is due to an unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Shockwave Player version before 12.1.0.150 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 12.1.0.150 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57277" );
	script_xref( name: "URL", value: "https://www.hkcert.org/my_url/en/alert/14031701" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/shockwave/apsb14-10.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Shockwave/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "12.1.0.150" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.1.0.150" );
	security_message( port: 0, data: report );
	exit( 0 );
}

