if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68691" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-4021" );
	script_bugtraq_id( 45122 );
	script_name( "FreeBSD Ports: krb5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: krb5

CVE-2010-4021
The Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) 1.7
does not properly restrict the use of TGT credentials for armoring TGS
requests, which might allow remote authenticated users to impersonate
a client by rewriting an inner request, aka a 'KrbFastReq forgery
issue.'" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
software upgrades." );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-007.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/4ccbd40d-03f7-11e0-bf50-001a926c7637.html" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
txt = "";
vuln = FALSE;
bver = portver( pkg: "krb5" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.7.0" ) >= 0 && revcomp( a: bver, b: "1.8.0" ) < 0){
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

