CPE = "cpe:/o:sonicwall:sma_100_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107119" );
	script_version( "2020-02-21T04:13:16+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-02-21 04:13:16 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "creation_date", value: "2017-01-09 13:26:09 +0700 (Mon, 09 Jan 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell SonicWALL SMA 8.1 XSS / CSRForgery Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Dell SonicWALL Secure Mobile Access and prone to
  a cross-site scripting / cross-site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "SonicWALL SMA suffers from an XSS issue due to a failure to properly sanitize
  user-supplied input to several parameters." );
	script_tag( name: "impact", value: "Attackers can exploit this weakness to execute arbitrary HTML and script code
  in a user's browser session. The WAF was bypassed via form-based CSRF." );
	script_tag( name: "affected", value: "Dell SonicWALL SMA 100 versions 8.1.0.x." );
	script_tag( name: "solution", value: "Update to version 8.1.0.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5392.php" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dell_sonicwall_sma_sra_consolidation.sc" );
	script_mandatory_keys( "sonicwall/sra_sma/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^8\\.1" ) && version_is_less( version: version, test_version: "8.1.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.1.0.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

