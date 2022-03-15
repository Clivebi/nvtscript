if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892762" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-39365" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-30 18:42:00 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-09-22 01:00:17 +0000 (Wed, 22 Sep 2021)" );
	script_name( "Debian LTS: Security Advisory for grilo (DLA-2762-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/09/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2762-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2762-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'grilo'
  package(s) announced via the DLA-2762-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in grilo, a framework for discovering and browsing
media. Due to missing TLS certificate verification, users are vulnerable
to network MITM attacks." );
	script_tag( name: "affected", value: "'grilo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.3.2-2+deb9u1.

We recommend that you upgrade your grilo packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-grilo-0.3", ver: "0.3.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgrilo-0.3-0", ver: "0.3.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgrilo-0.3-bin", ver: "0.3.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgrilo-0.3-dev", ver: "0.3.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgrilo-0.3-doc", ver: "0.3.2-2+deb9u1", rls: "DEB9" ) )){
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

