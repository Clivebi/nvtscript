if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891522" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2018-16151", "CVE-2018-16152" );
	script_name( "Debian LTS: Security Advisory for strongswan (DLA-1522-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-27 00:00:00 +0200 (Thu, 27 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-01 01:15:00 +0000 (Sun, 01 Dec 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00032.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.2.1-6+deb8u7.

We recommend that you upgrade your strongswan packages." );
	script_tag( name: "summary", value: "Sze Yiu Chau and his team from Purdue University and The University of
Iowa found several security issues in the gmp plugin for strongSwan,
an IKE/IPsec suite.

CVE-2018-16151

The OID parser in the ASN.1 code in gmp allows any number of random
bytes after a valid OID.

CVE-2018-16152

The algorithmIdentifier parser in the ASN.1 code in gmp doesn't
enforce a NULL value for the optional parameter which is not used
with any PKCS#1 algorithm." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.2.1-6+deb8u7", rls: "DEB8" ) )){
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

