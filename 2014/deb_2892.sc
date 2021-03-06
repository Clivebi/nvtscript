if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702892" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2001-1593", "CVE-2014-0466" );
	script_name( "Debian Security Advisory DSA 2892-1 (a2ps - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-31 00:00:00 +0200 (Mon, 31 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2892.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "a2ps on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed
in version 1:4.14-1.1+deb6u1.

For the stable distribution (wheezy), these problems have been fixed in
version 1:4.14-1.1+deb7u1.

For the testing distribution (jessie) and the unstable distribution
(sid), these problems will be fixed soon.

We recommend that you upgrade your a2ps packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in a2ps, an Anything to
PostScript
converter and pretty-printer. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2001-1593
The spy_user function which is called when a2ps is invoked with the

  - -debug flag insecurely used temporary files.

CVE-2014-0466
Brian M. Carlson reported that a2ps's fixps script does not invoke
gs with the -dSAFER option. Consequently executing fixps on a
malicious PostScript file could result in files being deleted or
arbitrary commands being executed with the privileges of the user
running fixps." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "a2ps", ver: "1:4.14-1.1+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "a2ps", ver: "1:4.14-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

