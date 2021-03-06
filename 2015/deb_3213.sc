if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703213" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-0556", "CVE-2015-0557", "CVE-2015-2782" );
	script_name( "Debian Security Advisory DSA 3213-1 (arj - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-06 00:00:00 +0200 (Mon, 06 Apr 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3213.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "arj on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 3.10.22-10+deb7u1.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 3.10.22-13.

For the unstable distribution (sid), these problems have been fixed in
version 3.10.22-13.

We recommend that you upgrade your arj packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have
been discovered in arj, an open source version of the arj archiver. The
Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0556
Jakub Wilk discovered that arj follows symlinks created during
unpacking of an arj archive. A remote attacker could use this flaw
to perform a directory traversal attack if a user or automated
system were tricked into processing a specially crafted arj archive.

CVE-2015-0557
Jakub Wilk discovered that arj does not sufficiently protect from
directory traversal while unpacking an arj archive containing file
paths with multiple leading slashes. A remote attacker could use
this flaw to write to arbitrary files if a user or automated system
were tricked into processing a specially crafted arj archive.

CVE-2015-2782
Jakub Wilk and Guillem Jover discovered a buffer overflow
vulnerability in arj. A remote attacker could use this flaw to cause
an application crash or, possibly, execute arbitrary code with the
privileges of the user running arj." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "arj", ver: "3.10.22-10+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

