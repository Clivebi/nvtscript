if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892458" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-13666", "CVE-2020-13671" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-15 04:15:00 +0000 (Tue, 15 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-20 04:00:30 +0000 (Fri, 20 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for drupal7 (DLA-2458-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00035.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2458-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the DLA-2458-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in Drupal, a fully-featured content
management framework.

CVE-2020-13666

The Drupal AJAX API did not disable JSONP by default, which could
lead to cross-site scripting.

For setups that relied on Drupal's AJAX API for JSONP requests,
either JSONP will need to be re-enabled, or the jQuery AJAX API will
have to be used instead.

See the upstream advisory for more details:

CVE-2020-13671

Drupal failed to sanitize filenames on uploaded files, which could
lead to those files being served as the wrong MIME type, or being
executed depending on the server configuration.

It is also recommended to check previously uploaded files for
malicious extensions. For more details see the upstream advisory:" );
	script_tag( name: "affected", value: "'drupal7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
7.52-2+deb9u12.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u12", rls: "DEB9" ) )){
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

