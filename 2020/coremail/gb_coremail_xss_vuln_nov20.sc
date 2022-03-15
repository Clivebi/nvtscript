if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112848" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-11-30 10:29:11 +0000 (Mon, 30 Nov 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-30 16:34:00 +0000 (Mon, 30 Nov 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2020-29133" );
	script_name( "Coremail XT <= 5.0 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_coremailxt_detect.sc" );
	script_mandatory_keys( "coremail/detected" );
	script_tag( name: "summary", value: "Coremail XT is prone to a cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "jsp/upload.jsp allows XSS via an uploaded personal signature,
  e.g. by injecting a .jpg.html filename in the signImgFile parameter." );
	script_tag( name: "impact", value: "Successful exploitation would allow to permanently modify the
  site's content, including injection of malicious code." );
	script_tag( name: "affected", value: "Coremail XT through version 5.0." );
	script_tag( name: "solution", value: "No known solution is available as of 08th July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	exit( 0 );
}
CPE = "cpe:/a:mailtech:coremail";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "5.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

