if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891265" );
	script_version( "2020-01-29T08:22:52+0000" );
	script_cve_id( "CVE-2013-1418", "CVE-2014-5351", "CVE-2014-5353", "CVE-2014-5355", "CVE-2016-3119", "CVE-2016-3120" );
	script_name( "Debian LTS: Security Advisory for krb5 (DLA-1265-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:22:52 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00040.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "krb5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.10.1+dfsg-5+deb7u9.

We recommend that you upgrade your krb5 packages." );
	script_tag( name: "summary", value: "Kerberos, a system for authenticating users and services on a network,
was affected by several vulnerabilities. The Common Vulnerabilities
and Exposures project identifies the following issues.

CVE-2013-1418
Kerberos allows remote attackers to cause a denial of service
(NULL pointer dereference and daemon crash) via a crafted request
when multiple realms are configured.

CVE-2014-5351
Kerberos sends old keys in a response to a -randkey -keepold
request, which allows remote authenticated users to forge tickets by
leveraging administrative access.

CVE-2014-5353
When the KDC uses LDAP, allows remote authenticated users to cause a
denial of service (daemon crash) via a successful LDAP query with no
results, as demonstrated by using an incorrect object type for a
password policy.

CVE-2014-5355
Kerberos expects that a krb5_read_message data field is represented
as a string ending with a '\\0' character, which allows remote
attackers to (1) cause a denial of service (NULL pointer
dereference) via a zero-byte version string or (2) cause a denial of
service (out-of-bounds read) by omitting the '\\0' character,

CVE-2016-3119
Kerberos allows remote authenticated users to cause a denial of
service (NULL pointer dereference and daemon crash) via a crafted
request to modify a principal.

CVE-2016-3120
Kerberos allows remote authenticated users to cause a denial of
service (NULL pointer dereference and daemon crash) via an S4U2Self
request." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-doc", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-gss-samples", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-locales", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-multidev", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-pkinit", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "krb5-user", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgssapi-krb5-2", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgssrpc4", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libk5crypto3", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkadm5clnt-mit8", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkadm5srv-mit8", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkdb5-6", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5-3", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5-dbg", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5-dev", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libkrb5support0", ver: "1.10.1+dfsg-5+deb7u9", rls: "DEB7" ) )){
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

