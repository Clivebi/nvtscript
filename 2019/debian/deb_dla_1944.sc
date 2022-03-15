if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891944" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-12412" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-30 14:39:00 +0000 (Mon, 30 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-10-04 02:00:07 +0000 (Fri, 04 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for libapreq2 (DLA-1944-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1944-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/939937" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libapreq2'
  package(s) announced via the DLA-1944-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a remotely-exploitable null pointer
dereference in libapreq2, a library for manipulating HTTP requests." );
	script_tag( name: "affected", value: "'libapreq2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in libapreq2 version
2.13-4+deb8u1.

We recommend that you upgrade your libapreq2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-apreq2", ver: "2.13-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-request-perl", ver: "2.13-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapreq2-3", ver: "2.13-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapreq2-dev", ver: "2.13-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapreq2-doc", ver: "2.13-4+deb8u1", rls: "DEB8" ) )){
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

