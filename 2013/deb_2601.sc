if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702601" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-6085" );
	script_name( "Debian Security Advisory DSA 2601-1 (gnupg, gnupg2 - missing input sanitation)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-06 00:00:00 +0100 (Sun, 06 Jan 2013)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2601.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "gnupg, gnupg2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.4.10-4+squeeze1 of gnupg and version 2.0.14-2+squeeze1 of
gnupg2.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem has been fixed in version 1.4.12-7 of gnupg and
version 2.0.19-2 of gnupg2.

We recommend that you upgrade your gnupg and/or gnupg2 packages." );
	script_tag( name: "summary", value: "KB Sriram discovered that GnuPG, the GNU Privacy Guard did not
sufficiently sanitise public keys on import, which could lead to
memory and keyring corruption.

The problem affects both version 1, in the gnupg package, and
version two, in the gnupg2
package." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnupg-agent", ver: "2.0.14-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.14-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgsm", ver: "2.0.14-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg-agent", ver: "2.0.19-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.19-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgsm", ver: "2.0.19-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "scdaemon", ver: "2.0.19-2", rls: "DEB7" ) ) != NULL){
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

