if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891736" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-7524" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for dovecot (DLA-1736-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00038.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1736-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot'
  package(s) announced via the DLA-1736-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A security vulnerability was discovered in the Dovecot email server.
When reading FTS headers from the Dovecot index, the input buffer
size is not bounds-checked. An attacker with the ability to modify
dovecot indexes, can take advantage of this flaw for privilege
escalation or the execution of arbitrary code with the permissions of
the dovecot user. Only installations using the FTS plugins are affected." );
	script_tag( name: "affected", value: "'dovecot' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1:2.2.13-12~deb8u6.

We recommend that you upgrade your dovecot packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dovecot-core", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-dbg", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-dev", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-gssapi", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-imapd", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-ldap", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-lmtpd", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-lucene", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-managesieved", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-mysql", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-pgsql", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-pop3d", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-sieve", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-solr", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dovecot-sqlite", ver: "1:2.2.13-12~deb8u6", rls: "DEB8" ) )){
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

