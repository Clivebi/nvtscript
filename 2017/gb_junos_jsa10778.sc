CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106752" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_cve_id( "CVE-2017-2313" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos BGP UPDATE DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	script_tag( name: "summary", value: "Junos OS is prone to denial of service vulnerability when receiving BGP
UPDATE messages." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "insight", value: "Junos OS 15.1 and later releases may be impacted by the receipt of a
crafted BGP UPDATE which can lead to an rpd (routing process daemon) crash and restart.  Repeated crashes of the
rpd daemon can result in an extended denial of service condition." );
	script_tag( name: "impact", value: "An attacker may cause a denial of service condition." );
	script_tag( name: "affected", value: "Junos OS 15.1, 16.1 and 16.2" );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10778" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^15" )){
	if( ( revcomp( a: version, b: "15.1F2-S15" ) < 0 ) && ( revcomp( a: version, b: "15.1F" ) >= 0 ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.1F2-S15" );
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
			if( ( revcomp( a: version, b: "15.1X49-D78" ) < 0 ) && ( revcomp( a: version, b: "15.1X49" ) >= 0 ) ){
				report = report_fixed_ver( installed_version: version, fixed_version: "15.1X49-D78" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
			else {
				if(( revcomp( a: version, b: "15.1X53-D63" ) < 0 ) && ( revcomp( a: version, b: "15.1X53" ) >= 0 )){
					report = report_fixed_ver( installed_version: version, fixed_version: "15.1X53-D63" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
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
		if(( revcomp( a: version, b: "16.2R2" ) < 0 ) && ( revcomp( a: version, b: "16.2" ) >= 0 )){
			report = report_fixed_ver( installed_version: version, fixed_version: "16.2R2" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

