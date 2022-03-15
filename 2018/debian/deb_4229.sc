if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704229" );
	script_version( "2021-06-17T04:16:32+0000" );
	script_cve_id( "CVE-2018-10811", "CVE-2018-5388" );
	script_name( "Debian Security Advisory DSA 4229-1 (strongswan - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-14 00:00:00 +0200 (Thu, 14 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-18 14:28:00 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4229.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "strongswan on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 5.2.1-6+deb8u6.

For the stable distribution (stretch), these problems have been fixed in
version 5.5.1-4+deb9u2.

We recommend that you upgrade your strongswan packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/strongswan" );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in strongSwan, an IKE/IPsec suite.

CVE-2018-5388
The stroke plugin did not verify the message length when reading from its
control socket. This vulnerability could lead to denial of service. On
Debian write access to the socket requires root permission on default
configuration.

CVE-2018-10811
A missing variable initialization in IKEv2 key derivation could lead to a
denial of service (crash of the charon IKE daemon) if the openssl plugin is
used in FIPS mode and the negotiated PRF is HMAC-MD5." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "charon-systemd", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-pki", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-scepclient", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-swanctl", ver: "5.5.1-4+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "charon-cmd", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcharon-extra-plugins", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-extra-plugins", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libstrongswan-standard-plugins", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-charon", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-dbg", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ike", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev1", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-ikev2", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-libcharon", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-nm", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "strongswan-starter", ver: "5.2.1-6+deb8u6", rls: "DEB8" ) )){
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

