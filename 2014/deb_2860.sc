if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702860" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-1921" );
	script_name( "Debian Security Advisory DSA 2860-1 (parcimonie - information disclosure)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-11 00:00:00 +0100 (Tue, 11 Feb 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2860.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "parcimonie on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.7.1-1+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.1-1.

We recommend that you upgrade your parcimonie packages." );
	script_tag( name: "summary", value: "Holger Levsen discovered that parcimonie, a privacy-friendly helper to
refresh a GnuPG keyring, is affected by a design problem that undermines
the usefulness of this piece of software in the intended threat model.

When using parcimonie with a large keyring (1000 public keys or more),
it would always sleep exactly ten minutes between two key fetches. This
can probably be used by an adversary who can watch enough key fetches to
correlate multiple key fetches with each other, which is what parcimonie
aims at protecting against. Smaller keyrings are affected to a smaller
degree. This problem is slightly mitigated when using a HKP(s) pool as
the configured GnuPG keyserver." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "parcimonie", ver: "0.7.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

