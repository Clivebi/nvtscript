if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703206" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2014-9706", "CVE-2015-0838" );
	script_name( "Debian Security Advisory DSA 3206-1 (dulwich - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-28 00:00:00 +0100 (Sat, 28 Mar 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3206.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dulwich on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 0.8.5-2+deb7u2.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 0.9.7-3.

For the unstable distribution (sid), these problems have been fixed in
version 0.10.1-1.

We recommend that you upgrade your dulwich packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have
been discovered in Dulwich, a Python implementation of the file formats
and protocols used by the Git version control system. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-9706
It was discovered that Dulwich allows writing to files under .git/
when checking out working trees. This could lead to the execution of
arbitrary code with the privileges of the user running an
application based on Dulwich.

CVE-2015-0838
Ivan Fratric of the Google Security Team has found a buffer
overflow in the C implementation of the apply_delta() function,
used when accessing Git objects in pack files. An attacker could
take advantage of this flaw to cause the execution of arbitrary
code with the privileges of the user running a Git server or client
based on Dulwich." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-dulwich", ver: "0.8.5-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-dulwich-dbg", ver: "0.8.5-2+deb7u2", rls: "DEB7" ) ) != NULL){
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

