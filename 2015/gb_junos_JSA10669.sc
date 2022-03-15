CPE = "cpe:/o:juniper:junos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105943" );
	script_cve_id( "CVE-2011-1944", "CVE-2012-5134", "CVE-2012-0841", "CVE-2013-2877", "CVE-2013-0338" );
	script_bugtraq_id( 48056, 56684, 52107, 61050, 58180 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos Multiple xml2 Vulnerabilities" );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10669" );
	script_tag( name: "summary", value: "Multiple vulnerabilities in the libxml version used by Junos OS." );
	script_tag( name: "impact", value: "The vulnerabilities may lead to DoS attacks or arbitrary code
execution." );
	script_tag( name: "insight", value: "libxml2 has been updated from 2.7.6 to 2.9.1 in Junos OS to
address multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable OS build is present on the target host." );
	script_tag( name: "solution", value: "New builds of Junos OS software are available from Juniper." );
	script_tag( name: "affected", value: "Junos OS 11.4, 12.1, 12.2, 12.3, 13.1, 13.3 and 14.1" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-01-23 10:32:34 +0700 (Fri, 23 Jan 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_ssh_junos_get_version.sc", "gb_junos_snmp_version.sc" );
	script_mandatory_keys( "Junos/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(revcomp( a: version, b: "11.4R13" ) < 0){
	security_message( port: 0, data: version );
	exit( 0 );
}
if(IsMatchRegexp( version, "^12" )){
	if( revcomp( a: version, b: "12.1X44-D35" ) < 0 ){
		security_message( port: 0, data: version );
		exit( 0 );
	}
	else {
		if( ( revcomp( a: version, b: "12.1X45-D30" ) < 0 ) && ( revcomp( a: version, b: "12.1X45" ) >= 0 ) ){
			security_message( port: 0, data: version );
			exit( 0 );
		}
		else {
			if( ( revcomp( a: version, b: "12.1X46-D25" ) < 0 ) && ( revcomp( a: version, b: "12.1X46" ) >= 0 ) ){
				security_message( port: 0, data: version );
				exit( 0 );
			}
			else {
				if( ( revcomp( a: version, b: "12.1X47-D10" ) < 0 ) && ( revcomp( a: version, b: "12.1X47" ) >= 0 ) ){
					security_message( port: 0, data: version );
					exit( 0 );
				}
				else {
					if( ( revcomp( a: version, b: "12.2R9" ) < 0 ) && ( revcomp( a: version, b: "12.2" ) >= 0 ) ){
						security_message( port: 0, data: version );
						exit( 0 );
					}
					else {
						if(( revcomp( a: version, b: "12.3R7" ) < 0 ) && ( revcomp( a: version, b: "12.3" ) >= 0 )){
							security_message( port: 0, data: version );
							exit( 0 );
						}
					}
				}
			}
		}
	}
}
if(IsMatchRegexp( version, "^13" )){
	if( revcomp( a: version, b: "13.1R4-S2" ) < 0 ){
		security_message( port: 0, data: version );
		exit( 0 );
	}
	else {
		if(( revcomp( a: version, b: "13.3R3" ) < 0 ) && ( revcomp( a: version, b: "13.3" ) >= 0 )){
			security_message( port: 0, data: version );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^14" )){
	if(revcomp( a: version, b: "14.1R2" ) < 0){
		security_message( port: 0, data: version );
		exit( 0 );
	}
}
exit( 99 );

