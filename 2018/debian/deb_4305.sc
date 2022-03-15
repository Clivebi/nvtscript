if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704305" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2018-16151", "CVE-2018-16152" );
	script_name( "Debian Security Advisory DSA 4305-1 (strongswan - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-24 00:00:00 +0200 (Mon, 24 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-01 01:15:00 +0000 (Sun, 01 Dec 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4305.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 5.5.1-4+deb9u3.

We recommend that you upgrade your strongswan packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/strongswan" );
	script_tag( name: "summary", value: "Sze Yiu Chau and his team from Purdue University and The University of Iowa
found several issues in the gmp plugin for strongSwan, an IKE/IPsec suite.

Problems in the parsing and verification of RSA signatures could lead to a
Bleichenbacher-style low-exponent signature forgery in certificates and during
IKE authentication.

While the gmp plugin doesn't allow arbitrary data after the ASN.1 structure
(the original Bleichenbacher attack), the ASN.1 parser is not strict enough and
allows data in specific fields inside the ASN.1 structure.

Only installations using the gmp plugin are affected (on Debian OpenSSL plugin
has priority over GMP one for RSA operations), and only when using keys and
certificates (including ones from CAs) using keys with an exponent e = 3, which
is usually rare in practice.

CVE-2018-16151
The OID parser in the ASN.1 code in gmp allows any number of random bytes
after a valid OID.

CVE-2018-16152
The algorithmIdentifier parser in the ASN.1 code in gmp doesn't enforce a
NULL value for the optional parameter which is not used with any PKCS#1
algorithm." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "charon-systemd", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-pki", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-scepclient", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-swanctl", ver: "5.5.1-4+deb9u3", rls: "DEB9" ) )){
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

