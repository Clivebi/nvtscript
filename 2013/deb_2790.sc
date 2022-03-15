if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702790" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1739" );
	script_name( "Debian Security Advisory DSA 2790-1 (nss - uninitialized memory read)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-11-02 00:00:00 +0100 (Sat, 02 Nov 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2790.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "nss on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 2:3.14.4-1.

The packages in the stable distribution were updated to the latest patch
release 3.14.4 of the library to also include a regression bugfix for a
flaw that affects the libpkix certificate verification cache.

For the testing distribution (jessie), this problem has been fixed in
version 2:3.15.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 2:3.15.2-1.

We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "A flaw was found in the way the Mozilla Network Security Service library
(nss) read uninitialized data when there was a decryption failure. A
remote attacker could use this flaw to cause a denial of service
(application crash) for applications linked with the nss library.

The oldstable distribution (squeeze) is not affected by this problem." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.14.4-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "2:3.14.4-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.14.4-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.14.4-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.14.4-1", rls: "DEB7" ) ) != NULL){
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

