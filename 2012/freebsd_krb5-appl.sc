if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70585" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-4862" );
	script_version( "$Revision: 11762 $" );
	script_name( "FreeBSD Ports: krb5-appl" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: krb5-appl

CVE-2011-4862
Buffer overflow in libtelnet/encrypt.c in telnetd in FreeBSD 7.3
through 9.0, MIT Kerberos Version 5 Applications (aka krb5-appl) 1.0.2
and earlier, and Heimdal 1.5.1 and earlier allows remote attackers to
execute arbitrary code via a long encryption key, as exploited in the
wild in December 2011." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://security.FreeBSD.org/advisories/FreeBSD-SA-11:08.telnetd.asc" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/4ddc78dc-300a-11e1-a2aa-0016ce01e285.html" );
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
bver = portver( pkg: "krb5-appl" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.0.2_1" ) < 0){
	txt += "Package krb5-appl version " + bver + " is installed which is known to be vulnerable.\n";
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

