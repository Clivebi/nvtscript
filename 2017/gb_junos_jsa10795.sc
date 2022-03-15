CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140290" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-10 11:17:39 +0700 (Thu, 10 Aug 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-2347" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos MPLS DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	script_tag( name: "summary", value: "Junos OS is prone to a denial of service vulnerability in rpd when receiving
a malformed MPLS ping packet." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "A denial of service vulnerability in rpd daemon of Juniper Networks Junos
OS allows a malformed MPLS ping packet to crash the rpd daemon. Repeated crashes of the rpd daemon can result in
an extended denial of service condition for the device." );
	script_tag( name: "affected", value: "Junos OS 12.3X48, 13.3, 14.1, 14.1X53, 14.2, 15.1, 15.1X49, 15.1X53,
16.1." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10795" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^12" )){
	if(( revcomp( a: version, b: "12.3X48-D50" ) < 0 ) && ( revcomp( a: version, b: "12.3X48" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "12.3X48-D50" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^13" )){
	if(( revcomp( a: version, b: "13.3R10" ) < 0 ) && ( revcomp( a: version, b: "13.3R" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "13.3R10" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^14" )){
	if( ( revcomp( a: version, b: "14.1R9" ) < 0 ) && ( revcomp( a: version, b: "14.1R" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.1R9" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "14.1X53-D42" ) < 0 ) && ( revcomp( a: version, b: "14.1X53" ) >= 0 ) ){
			report = report_fixed_ver( installed_version: version, fixed_version: "14.1X53-D42" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
		else {
			if(( revcomp( a: version, b: "14.2R8" ) < 0 ) && ( revcomp( a: version, b: "14.2R" ) >= 0 )){
				report = report_fixed_ver( installed_version: version, fixed_version: "14.2R8" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
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
			if( ( revcomp( a: version, b: "15.1X49-D100" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 ) ){
				report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D100" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
			else {
				if(( revcomp( a: version, b: "15.1X53-D70" ) < 0 ) && ( revcomp( a: version, b: "15.1X53" ) >= 0 )){
					report = report_fixed_ver( installed_version: version, fixed_version: "15.1X53-D70" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
	}
}
if(IsMatchRegexp( version, "^16" )){
	if(( revcomp( a: version, b: "16.1R4" ) < 0 ) && ( revcomp( a: version, b: "16.1R" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.1R4" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

