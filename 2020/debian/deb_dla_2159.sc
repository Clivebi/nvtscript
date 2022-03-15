if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892159" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-9359" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-26 04:00:12 +0000 (Thu, 26 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for okular (DLA-2159-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00033.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2159-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/954891" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'okular'
  package(s) announced via the DLA-2159-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mickael Karatekin from Sysdream Labs discovered that the Okular
document viewer allows code execution via an action link in a PDF
document." );
	script_tag( name: "affected", value: "'okular' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4:4.14.2-2+deb8u2.

We recommend that you upgrade your okular packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libokularcore5", ver: "4:4.14.2-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "okular", ver: "4:4.14.2-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "okular-dbg", ver: "4:4.14.2-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "okular-dev", ver: "4:4.14.2-2+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "okular-extra-backends", ver: "4:4.14.2-2+deb8u2", rls: "DEB8" ) )){
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

