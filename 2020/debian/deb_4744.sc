if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704744" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-16145" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-24 18:15:00 +0000 (Thu, 24 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-08-13 03:00:08 +0000 (Thu, 13 Aug 2020)" );
	script_name( "Debian: Security Advisory for roundcube (DSA-4744-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4744.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4744-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'roundcube'
  package(s) announced via the DSA-4744-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that roundcube, a skinnable AJAX based webmail
solution for IMAP servers, is prone to cross-site scripting
vulnerabilities in handling invalid svg and math tag content." );
	script_tag( name: "affected", value: "'roundcube' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.3.15+dfsg.1-1~deb10u1.

We recommend that you upgrade your roundcube packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "roundcube", ver: "1.3.15+dfsg.1-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-core", ver: "1.3.15+dfsg.1-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "1.3.15+dfsg.1-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "1.3.15+dfsg.1-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "1.3.15+dfsg.1-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-sqlite3", ver: "1.3.15+dfsg.1-1~deb10u1", rls: "DEB10" ) )){
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

