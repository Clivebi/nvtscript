if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69595" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0285" );
	script_name( "FreeBSD Ports: krb5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: krb5

CVE-2011-0285
The process_chpw_request function in schpw.c in the password-changing
functionality in kadmind in MIT Kerberos 5 (aka krb5) 1.7 through 1.9
frees an invalid pointer, which allows remote attackers to execute
arbitrary code or cause a denial of service (daemon crash) via a
crafted request that triggers an error condition." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2011-004.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/6a3c3e5c-66cb-11e0-a116-c535f3aa24f0.html" );
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
bver = portver( pkg: "krb5" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.7" ) >= 0 && revcomp( a: bver, b: "1.9" ) <= 0){
	txt += "Package krb5 version " + bver + " is installed which is known to be vulnerable.\n";
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

