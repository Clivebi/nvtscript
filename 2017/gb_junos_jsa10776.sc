CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106754" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-24 11:29:00 +0000 (Thu, 24 Jan 2019)" );
	script_cve_id( "CVE-2016-9311", "CVE-2016-9310", "CVE-2015-7973", "CVE-2015-7979", "CVE-2016-7431", "CVE-2015-8158", "CVE-2016-7429", "CVE-2016-7427" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos Multiple NTP Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	script_tag( name: "summary", value: "Junos OS is prone to multiple vulnerabilities in NTP." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "NTP.org and FreeBSD have published security advisories for vulnerabilities
resolved in ntpd which impact Junos OS." );
	script_tag( name: "affected", value: "Junos OS 12.3X48, 14.1, 14.2, 15.1, 16.1 and 16.2" );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10776" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^12" )){
	if(( revcomp( a: version, b: "12.3X48-D45" ) < 0 ) && ( revcomp( a: version, b: "12.3X48" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "12.3X48-D45" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^14" )){
	if( revcomp( a: version, b: "14.1R8-S3" ) < 0 ){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.1R8-S3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(( revcomp( a: version, b: "14.2R7-S6" ) < 0 ) && ( revcomp( a: version, b: "14.2" ) >= 0 )){
			report = report_fixed_ver( installed_version: version, fixed_version: "14.2R7-S6" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^15" )){
	if( ( revcomp( a: version, b: "15.1F7" ) < 0 ) && ( revcomp( a: version, b: "15.1F" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.1F7" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "15.1R6" ) < 0 ) && ( revcomp( a: version, b: "15.1R" ) >= 0 ) ){
			report = report_fixed_ver( installed_version: version, fixed_version: "15.1R6" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "15.1X49-D80" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 )){
				report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D80" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
if(IsMatchRegexp( version, "^16" )){
	if( revcomp( a: version, b: "16.1R3-S3" ) < 0 ){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.1R3-S3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(( revcomp( a: version, b: "16.2R1-S3" ) < 0 ) && ( revcomp( a: version, b: "16.2" ) >= 0 )){
			report = report_fixed_ver( installed_version: version, fixed_version: "16.2R1-S3" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

