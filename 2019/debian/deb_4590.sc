if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704590" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-19783" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 05:15:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-12-21 03:00:07 +0000 (Sat, 21 Dec 2019)" );
	script_name( "Debian Security Advisory DSA 4590-1 (cyrus-imapd - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4590.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4590-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the DSA-4590-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the lmtpd component of the Cyrus IMAP server
created mailboxes with administrator privileges if the fileinto
was
used, bypassing ACL checks." );
	script_tag( name: "affected", value: "'cyrus-imapd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 2.5.10-3+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 3.0.8-6+deb10u3.

We recommend that you upgrade your cyrus-imapd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cyrus-admin", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-caldav", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-clients", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-common", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-dev", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-doc", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-imapd", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-murder", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-nntpd", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-pop3d", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-replication", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcyrus-imap-perl", ver: "2.5.10-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-admin", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-caldav", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-clients", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-common", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-dev", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-doc", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-imapd", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-murder", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-nntpd", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-pop3d", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cyrus-replication", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcyrus-imap-perl", ver: "3.0.8-6+deb10u3", rls: "DEB10" ) )){
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

