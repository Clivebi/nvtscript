if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892472" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-28896" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-28 14:43:00 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-12-01 04:00:08 +0000 (Tue, 01 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for mutt (DLA-2472-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00048.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2472-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mutt'
  package(s) announced via the DLA-2472-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Mutt, a text-based Mail User Agent, invalid IMAP server responses
were not properly handled, potentially resulting in authentication
credentials being exposed or man-in-the-middle attacks." );
	script_tag( name: "affected", value: "'mutt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.7.2-1+deb9u4.

We recommend that you upgrade your mutt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mutt", ver: "1.7.2-1+deb9u4", rls: "DEB9" ) )){
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

