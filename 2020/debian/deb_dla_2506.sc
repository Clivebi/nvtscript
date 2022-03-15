if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892506" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-29600", "CVE-2020-35176" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 20:52:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-24 04:00:12 +0000 (Thu, 24 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for awstats (DLA-2506-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00035.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2506-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/891469" );
	script_xref( name: "URL", value: "https://bugs.debian.org/977190" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'awstats'
  package(s) announced via the DLA-2506-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Awstats, a web server log analyzer, was
vulnerable to path traversal attacks. A remote unauthenticated
attacker could leverage that to perform arbitrary code execution. The
previous fix did not fully address the issue when the default
/etc/awstats/awstats.conf is not present." );
	script_tag( name: "affected", value: "'awstats' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
7.6+dfsg-1+deb9u2.

We recommend that you upgrade your awstats packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "awstats", ver: "7.6+dfsg-1+deb9u2", rls: "DEB9" ) )){
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
