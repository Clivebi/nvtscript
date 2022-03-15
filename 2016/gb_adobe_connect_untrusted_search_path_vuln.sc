CPE = "cpe:/a:adobe:connect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808062" );
	script_version( "2020-11-12T10:28:08+0000" );
	script_cve_id( "CVE-2016-4118" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 10:28:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-06-07 16:34:52 +0530 (Tue, 07 Jun 2016)" );
	script_name( "Adobe Connect Untrusted Search Path Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_connect_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "adobe/connect/installed" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/connect/apsb16-17.html" );
	script_tag( name: "summary", value: "The host is installed with Adobe Connect
  shipping an Adobe Connect Add-In for Windows which is prone to a untrusted
  search path vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  Adobe Connect Add-In installer while validating the path." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  users of the System which is using the vulnerable Adobe Connect Add-In to
  gain privileges via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Connect versions before 9.5.3." );
	script_tag( name: "solution", value: "Upgrade to Adobe Connect version 9.5.3 or
  later which ships a non-vulnerable Adobe Connect Add-In." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!acPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!acVer = get_app_version( cpe: CPE, port: acPort )){
	exit( 0 );
}
if(version_is_less( version: acVer, test_version: "9.5.3" )){
	report = report_fixed_ver( installed_version: acVer, fixed_version: "9.5.3" );
	security_message( data: report, port: acPort );
	exit( 0 );
}

