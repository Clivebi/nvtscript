if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892388" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2018-12404", "CVE-2018-18508", "CVE-2019-11719", "CVE-2019-11729", "CVE-2019-11745", "CVE-2019-17006", "CVE-2019-17007", "CVE-2020-12399", "CVE-2020-12400", "CVE-2020-12401", "CVE-2020-12402", "CVE-2020-12403", "CVE-2020-6829" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 16:59:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-09-30 03:00:21 +0000 (Wed, 30 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for nss (DLA-2388-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00029.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2388-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/921614" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961752" );
	script_xref( name: "URL", value: "https://bugs.debian.org/963152" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the DLA-2388-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Various vulnerabilities were fixed in nss,
the Network Security Service libraries.

CVE-2018-12404

Cache side-channel variant of the Bleichenbacher attack.

CVE-2018-18508

NULL pointer dereference in several CMS functions resulting in a
denial of service.

CVE-2019-11719

Out-of-bounds read when importing curve25519 private key.

CVE-2019-11729

Empty or malformed p256-ECDH public keys may trigger a segmentation
fault.

CVE-2019-11745

Out-of-bounds write when encrypting with a block cipher.

CVE-2019-17006

Some cryptographic primitives did not check the length of the input
text, potentially resulting in overflows.

CVE-2019-17007

Handling of Netscape Certificate Sequences may crash with a NULL
dereference leading to a denial of service.

CVE-2020-12399

Force a fixed length for DSA exponentiation.

CVE-2020-6829
CVE-2020-12400

Side channel attack on ECDSA signature generation.

CVE-2020-12401

ECDSA timing attack mitigation bypass.

CVE-2020-12402

Side channel vulnerabilities during RSA key generation.

CVE-2020-12403

CHACHA20-POLY1305 decryption with undersized tag leads to
out-of-bounds read." );
	script_tag( name: "affected", value: "'nss' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2:3.26.2-1.1+deb9u2.

We recommend that you upgrade your nss packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.26.2-1.1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.26.2-1.1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.26.2-1.1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.26.2-1.1+deb9u2", rls: "DEB9" ) )){
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
exit( 0 );

