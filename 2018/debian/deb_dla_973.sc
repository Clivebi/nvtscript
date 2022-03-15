if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890973" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-9022", "CVE-2017-9023" );
	script_name( "Debian LTS: Security Advisory for strongswan (DLA-973-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-16 14:36:00 +0000 (Tue, 16 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00001.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.5.2-1.5+deb7u9.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "Two denial of service vulnerabilities were identified in strongSwan, an
IKE/IPsec suite, using Google's OSS-Fuzz fuzzing project.

CVE-2017-9022

RSA public keys passed to the gmp plugin aren't validated sufficiently
before attempting signature verification, so that invalid input might
lead to a floating point exception and crash of the process.
A certificate with an appropriately prepared public key sent by a peer
could be used for a denial-of-service attack.

CVE-2017-9023

ASN.1 CHOICE types are not correctly handled by the ASN.1 parser when
parsing X.509 certificates with extensions that use such types. This could
lead to infinite looping of the thread parsing a specifically crafted
certificate." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-nm", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-starter", ver: "4.5.2-1.5+deb7u9", rls: "DEB7" ) )){
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

