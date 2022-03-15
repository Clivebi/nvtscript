if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69758" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-1922" );
	script_name( "FreeBSD Ports: unbound" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: unbound

CVE-2011-1922
daemon/worker.c in Unbound 1.x before 1.4.10, when debugging
functionality and the interface-automatic option are enabled, allows
remote attackers to cause a denial of service (assertion failure and
daemon exit) via a crafted DNS request that triggers improper error
handling." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://unbound.nlnetlabs.nl/downloads/CVE-2011-1922.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/dc96ac1f-86b1-11e0-9e85-00215af774f0.html" );
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
bver = portver( pkg: "unbound" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.4.10" ) < 0){
	txt += "Package unbound version " + bver + " is installed which is known to be vulnerable.\n";
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

