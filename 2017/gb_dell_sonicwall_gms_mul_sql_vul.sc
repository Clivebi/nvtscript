if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107121" );
	script_version( "2020-11-04T10:48:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-04 10:48:08 +0000 (Wed, 04 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-01-11 10:12:05 +0700 (Wed, 11 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 95155 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell SonicWALL GMS/Analyzer 8.x < 8.2 Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dell_sonicwall_gms_detection.sc" );
	script_mandatory_keys( "sonicwall/ums/detected" );
	script_tag( name: "summary", value: "Dell SonicWALL GMS/Analyzer are prone to multiple SQL vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SonicWALL GMS/Analyzer suffers from multiple SQL vulnerabilities
  because it does not sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "A successful exploit may allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Dell Sonicwall GMS/Analyzer 8.0 up to 8.1." );
	script_tag( name: "solution", value: "Update to version 8.2." );
	script_xref( name: "URL", value: "https://support.sonicwall.com/product-notification/215257?productName=SonicWALL%20GMS" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5388.php" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/95155/" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40977/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:sonicwall:global_management_system",
	 "cpe:/a:sonicwall:analyzer" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(IsMatchRegexp( vers, "^8\\.[01]" )){
	if(version_is_less( version: vers, test_version: "8.2" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "8.2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

