CPE = "cpe:/a:geovap:reliance-scada";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112150" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-07 08:23:03 +0100 (Thu, 07 Dec 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:25:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-16721" );
	script_bugtraq_id( 102031 );
	script_name( "Geovap Reliance SCADA XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_geovap_reliance_scada_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "geovap/reliance-scada/detected", "geovap/reliance-scada/version" );
	script_tag( name: "summary", value: "This host is running Geovap Reliance SCADA and is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability could allow an unauthenticated attacker
to inject arbitrary JavaScript in a specially crafted URL request that may allow for read/write access." );
	script_tag( name: "affected", value: "Reliance SCADA Version 4.7.3 Update 2 and prior." );
	script_tag( name: "solution", value: "Geovap has released Version 4.7.3 Update 3" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-17-334-02" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/102031" );
	script_xref( name: "URL", value: "https://www.reliance-scada.com/en/download" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_kb_item( "geovap/reliance-scada/version" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.7.3 Update 3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.3 Update 3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

