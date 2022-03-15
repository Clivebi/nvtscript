if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891643" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2018-20217", "CVE-2018-5729", "CVE-2018-5730" );
	script_name( "Debian LTS: Security Advisory for krb5 (DLA-1643-1)" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-28 00:00:00 +0100 (Mon, 28 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-21 15:47:00 +0000 (Tue, 21 Jan 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "krb5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie',
these problems have been fixed in version 1.12.1+dfsg-19+deb8u5.

We recommend that you upgrade your krb5 packages." );
	script_tag( name: "summary", value: "krb5, a MIT Kerberos implementation, had several flaws in LDAP DN
checking, which could be used to circumvent a DN containership check by
supplying special parameters to some calls.

Further an attacker could crash the KDC by making S4U2Self requests." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-doc", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-gss-samples", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-locales", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-multidev", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-otp", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-pkinit", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-user", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgssapi-krb5-2", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgssrpc4", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libk5crypto3", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkadm5clnt-mit9", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkadm5srv-mit9", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkdb5-7", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrad-dev", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrad0", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5-3", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5-dbg", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5-dev", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5support0", ver: "1.12.1+dfsg-19+deb8u5", rls: "DEB8" ) )){
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

