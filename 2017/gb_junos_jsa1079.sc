CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140289" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-10 11:02:59 +0700 (Thu, 10 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)" );
	script_cve_id( "CVE-2016-3074" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos libgd Heap Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	script_tag( name: "summary", value: "Junos OS is prone to a heap overflow vulnerability in libgd which allows
  remote attackers to cause a denial of service or potentially execute arbitrary code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "libgd is an open-source image library which is bundled with PHP version 4.3
  and above. An integer signedness vulnerability exists in libgd 2.1.1 which may result in a heap overflow when
  processing compressed gd2 data." );
	script_tag( name: "affected", value: "Junos OS 12.1X46, 12.3X48, 15.1X49, 14.2, 15.1, 15.1X53, 16.1, 16.2." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10798" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^12" )){
	if( ( revcomp( a: version, b: "12.1X46-D65" ) < 0 ) && ( revcomp( a: version, b: "12.1X46" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "12.1X46-D65" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(( revcomp( a: version, b: "12.3X48-D40" ) < 0 ) && ( revcomp( a: version, b: "12.3X48" ) >= 0 )){
			report = report_fixed_ver( installed_version: version, fixed_version: "12.3X48-D40" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^14" )){
	if(( revcomp( a: version, b: "14.2R8" ) < 0 ) && ( revcomp( a: version, b: "14.2R" ) >= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.2R8" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^15" )){
	if( ( revcomp( a: version, b: "15.1F7" ) < 0 ) && ( revcomp( a: version, b: "15.1F" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.1F7" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "15.1R5" ) < 0 ) && ( revcomp( a: version, b: "15.1R" ) >= 0 ) ){
			report = report_fixed_ver( installed_version: version, fixed_version: "15.1R5" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
		else {
			if( ( revcomp( a: version, b: "15.1X49-D70" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 ) ){
				report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D70" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
			else {
				if(( revcomp( a: version, b: "15.1X53-D47" ) < 0 ) && ( revcomp( a: version, b: "15.1X53" ) >= 0 )){
					report = report_fixed_ver( installed_version: version, fixed_version: "15.1X53-D47" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
	}
}
if(IsMatchRegexp( version, "^16" )){
	if( ( revcomp( a: version, b: "16.1R4" ) < 0 ) && ( revcomp( a: version, b: "16.1R" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.1R4" );
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
exit( 99 );

