if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70749" );
	script_cve_id( "CVE-2012-0802" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: spamdyke" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: spamdyke" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://secunia.com/advisories/47548/" );
	script_xref( name: "URL", value: "http://www.spamdyke.org/documentation/Changelog.txt" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/7d2336c2-4607-11e1-9f47-00e0815b8da8.html" );
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
bver = portver( pkg: "spamdyke" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.3.0" ) < 0){
	txt += "Package spamdyke version " + bver + " is installed which is known to be vulnerable.\n";
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

