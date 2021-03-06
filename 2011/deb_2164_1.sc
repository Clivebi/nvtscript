if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68999" );
	script_version( "2019-08-06T11:17:21+0000" );
	script_tag( name: "last_modification", value: "2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2011-0721" );
	script_name( "Debian Security Advisory DSA 2164-1 (shadow)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202164-1" );
	script_tag( name: "insight", value: "Kees Cook discovered that the chfn and chsh utilities do not properly
sanitize user input that includes newlines.  An attacker could use this
to corrupt passwd entries and may create users or groups in NIS
environments.

Packages in the oldstable distribution (lenny) are not affected by this
problem.

For the stable distribution (squeeze), this problem has been fixed in
version 1:4.1.4.2+svn3283-2+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your shadow packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to shadow
announced via advisory DSA 2164-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "login", ver: "1:4.1.4.2+svn3283-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "passwd", ver: "1:4.1.4.2+svn3283-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

