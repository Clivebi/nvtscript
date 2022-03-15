CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105264" );
	script_bugtraq_id( 72325 );
	script_cve_id( "CVE-2015-0235" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 12106 $" );
	script_name( "Palo Alto PAN-OS PAN-SA-2015-0002" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/29" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts may crash the application, denying service
to legitimate users." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Please ask the vendor for a patch or workaround" );
	script_tag( name: "summary", value: "The open source library 'glibc' has been
found to contain a recently discovered vulnerability (CVE-2015-0235, commonly
referred to as 'GHOST') that has been demonstrated to enable remote code
execution in some software. Palo Alto Networks software makes use of the
vulnerable library, however there is no known exploitable condition in PAN-OS
software enabled by this vulnerability at the time of this advisory. An update
to PAN-OS will be made available that addresses CVE-2015-0235 in a regularly
scheduled software maintenance update. (Ref # 74443)" );
	script_tag( name: "affected", value: "PAN-OS versions prior to PAN-OS 7.0.1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-04-23 13:30:05 +0200 (Thu, 23 Apr 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_is_less( version: version, test_version: "7.0.1" )){
	report = "Installed version: " + version + "\n" + "Fixed version:     7.0.1\n";
	if(model){
		report += "Model:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

