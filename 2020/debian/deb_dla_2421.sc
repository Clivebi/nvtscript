if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892421" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2018-7588", "CVE-2018-7589", "CVE-2018-7637", "CVE-2018-7638", "CVE-2018-7639", "CVE-2018-7640", "CVE-2018-7641", "CVE-2019-1010174" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-31 04:00:41 +0000 (Sat, 31 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for cimg (DLA-2421-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00033.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2421-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cimg'
  package(s) announced via the DLA-2421-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in cimg, a powerful image processing
library.

CVE-2019-1010174 is related to a missing string sanitization on URLs,
which might result in a command injection when loading a special crafted
image.

The other CVEs are about heap-based buffer over-reads or double frees when
loading a crafted image." );
	script_tag( name: "affected", value: "'cimg' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.7.9+dfsg-1+deb9u1.

We recommend that you upgrade your cimg packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cimg-dev", ver: "1.7.9+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cimg-doc", ver: "1.7.9+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cimg-examples", ver: "1.7.9+dfsg-1+deb9u1", rls: "DEB9" ) )){
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

