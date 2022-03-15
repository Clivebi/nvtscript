if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71367" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0009", "CVE-2011-2082", "CVE-2011-2083", "CVE-2011-2084", "CVE-2011-2085", "CVE-2011-4458", "CVE-2011-4459", "CVE-2011-4460" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:50 -0400 (Thu, 31 May 2012)" );
	script_name( "FreeBSD Ports: rt40" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  rt40
   rt38

CVE-2011-0009
Best Practical Solutions RT 3.x before 3.8.9rc2 and 4.x before
4.0.0rc4 uses the MD5 algorithm for password hashes, which makes it
easier for context-dependent attackers to determine cleartext
passwords via a brute-force attack on the database." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://blog.bestpractical.com/2012/05/security-vulnerabilities-in-rt.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/e0a969e4-a512-11e1-90b4-e0cb4e266481.html" );
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
bver = portver( pkg: "rt40" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.0" ) >= 0 && revcomp( a: bver, b: "4.0.6" ) < 0){
	txt += "Package rt40 version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "rt38" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.8.12" ) < 0){
	txt += "Package rt38 version " + bver + " is installed which is known to be vulnerable.\\n";
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

