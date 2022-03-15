if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891015" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2017-7526" );
	script_name( "Debian LTS: Security Advisory for libgcrypt11 (DLA-1015-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-05 00:00:00 +0100 (Mon, 05 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libgcrypt11 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in libgcrypt11 version
1.5.0-5+deb7u6.

We recommend that you upgrade your libgcrypt11 packages." );
	script_tag( name: "summary", value: "It was discovered that there was a key disclosure vulnerability in libgcrypt11
a library of cryptographic routines:

It is well known that constant-time implementations of modular exponentiation
cannot use sliding windows. However, software libraries such as Libgcrypt,
used by GnuPG, continue to use sliding windows. It is widely believed that,
even if the complete pattern of squarings and multiplications is observed
through a side-channel attack, the number of exponent bits leaked is not
sufficient to carry out a full key-recovery attack against RSA.
Specifically, 4-bit sliding windows leak only 40% of the bits, and 5-bit
sliding windows leak only 33% of the bits.

  - - Sliding right into disaster: Left-to-right sliding windows leak
<" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt11", ver: "1.5.0-5+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt11-dbg", ver: "1.5.0-5+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt11-dev", ver: "1.5.0-5+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt11-doc", ver: "1.5.0-5+deb7u6", rls: "DEB7" ) )){
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

