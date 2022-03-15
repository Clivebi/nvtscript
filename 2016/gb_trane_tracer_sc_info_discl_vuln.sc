CPE = "cpe:/a:trane:tracer_sc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106273" );
	script_version( "2020-11-12T09:36:23+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-09-20 17:00:53 +0700 (Tue, 20 Sep 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-0870" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Trane Tracer SC Information Exposure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_trane_tracer_sc_detect.sc" );
	script_mandatory_keys( "trane_tracer/detected" );
	script_tag( name: "summary", value: "Trane Tracer SC is prone to an information exposure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability allows an unauthorized party to obtain sensitive
information from the contents of configuration files not protected by the web server." );
	script_tag( name: "impact", value: "An unauthorized attacker can exploit this vulnerability to read sensitive
information from the contents of configuration files." );
	script_tag( name: "affected", value: "Versions 4.2.1134 and below." );
	script_tag( name: "solution", value: "Contact the vendor for an update." );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-16-259-03" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "4.2.1134" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Contact vendor" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

