if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72596" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-4445" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-26 12:47:32 -0500 (Mon, 26 Nov 2012)" );
	script_name( "FreeBSD Ports: FreeBSD" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: FreeBSD

CVE-2012-4445
Heap-based buffer overflow in the eap_server_tls_process_fragment
function in eap_server_tls_common.c in the EAP authentication server
in hostapd 0.6 through 1.0 allows remote attackers to cause a denial
of service (crash or abort) via a small 'TLS Message Length' value in
an EAP-TLS message with the 'More Fragments' flag set." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "FreeBSD" );
if(!isnull( bver ) && revcomp( a: bver, b: "8.3" ) >= 0 && revcomp( a: bver, b: "8.3_5" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "9.0" ) >= 0 && revcomp( a: bver, b: "9.0_5" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

