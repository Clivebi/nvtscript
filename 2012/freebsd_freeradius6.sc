if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72199" );
	script_cve_id( "CVE-2012-3547" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:25:48 -0400 (Sat, 15 Sep 2012)" );
	script_name( "FreeBSD Ports: freeradius" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: freeradius" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://freeradius.org/security.html" );
	script_xref( name: "URL", value: "http://www.pre-cert.de/advisories/PRE-SA-2012-06.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/3bbbe3aa-fbeb-11e1-8bd8-0022156e8794.html" );
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
bver = portver( pkg: "freeradius" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.1.10" ) >= 0 && revcomp( a: bver, b: "2.1.12_2" ) < 0){
	txt += "Package freeradius version " + bver + " is installed which is known to be vulnerable.\\n";
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

