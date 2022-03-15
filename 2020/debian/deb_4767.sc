if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704767" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-15005", "CVE-2020-25812", "CVE-2020-25813", "CVE-2020-25814", "CVE-2020-25815", "CVE-2020-25827", "CVE-2020-25828" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-14 03:15:00 +0000 (Mon, 14 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-09-27 03:00:14 +0000 (Sun, 27 Sep 2020)" );
	script_name( "Debian: Security Advisory for mediawiki (DSA-4767-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4767.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4767-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediawiki'
  package(s) announced via the DSA-4767-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were discovered in MediaWiki, a website engine
for collaborative work: SpecialUserRights could leak whether a user
existed or not, multiple code paths lacked HTML sanitisation allowing
for cross-site scripting and TOTP validation applied insufficient rate
limiting against brute force attempts." );
	script_tag( name: "affected", value: "'mediawiki' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1:1.31.10-1~deb10u1.

We recommend that you upgrade your mediawiki packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mediawiki", ver: "1:1.31.10-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mediawiki-classes", ver: "1:1.31.10-1~deb10u1", rls: "DEB10" ) )){
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

