CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106949" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-13 15:09:50 +0700 (Thu, 13 Jul 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)" );
	script_cve_id( "CVE-2017-3731", "CVE-2017-3732", "CVE-2016-7055" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos Multiple OpenSSL Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	script_tag( name: "summary", value: "Junos OS is prone to multiple vulnerabilities in OpenSSL" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "affected", value: "Junos OS 14.1, 14.1X53, 14.2, 15.1, 15.1X49, 15.1X53, 15.1X56, 16.1, 16.2,
17.1." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10775" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^14" )){
	if( ( revcomp( a: version, b: "14.1R9" ) < 0 ) && ( revcomp( a: version, b: "14.1R" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.1R9" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "14.1X53-D43" ) < 0 ) && ( revcomp( a: version, b: "14.1X53" ) >= 0 ) ){
			report = report_fixed_ver( installed_version: version, fixed_version: "14.1X53-D43" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "14.2R7-S6" ) < 0 ) && ( revcomp( a: version, b: "14.2R" ) >= 0 )){
				report = report_fixed_ver( installed_version: version, fixed_version: "14.2R7-S6" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
if(IsMatchRegexp( version, "^15" )){
	if( ( revcomp( a: version, b: "15.1F5-S7" ) < 0 ) && ( revcomp( a: version, b: "15.1F" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.1F5-S7" );
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
			if( ( revcomp( a: version, b: "15.1X49-D100" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 ) ){
				report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D100" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
			else {
				if( ( revcomp( a: version, b: "15.1X53-D47" ) < 0 ) && ( revcomp( a: version, b: "15.1X53" ) >= 0 ) ){
					report = report_fixed_ver( installed_version: version, fixed_version: "15.1X53-D47" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
				else {
					if(( revcomp( a: version, b: "15.1X56-D62" ) < 0 ) && ( revcomp( a: version, b: "15.1X56" ) >= 0 )){
						report = report_fixed_ver( installed_version: version, fixed_version: "15.1X56-D62" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
		}
	}
}
if(IsMatchRegexp( version, "^16" )){
	if( revcomp( a: version, b: "16.1R5" ) < 0 ){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.1R5" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(( revcomp( a: version, b: "16.2R2" ) < 0 ) && ( revcomp( a: version, b: "16.2R" ) >= 0 )){
			report = report_fixed_ver( installed_version: version, fixed_version: "16.2R2" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^17" )){
	if(revcomp( a: version, b: "17.1R2" ) < 0){
		report = report_fixed_ver( installed_version: version, fixed_version: "17.1R2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

