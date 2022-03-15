if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892721" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-32610" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-06 20:47:00 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-27 03:00:17 +0000 (Tue, 27 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for drupal7 (DLA-2721-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2721-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2721-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the DLA-2721-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Drupal project uses the pear Archive_Tar library, which has
released a security update that impacts Drupal.

The vulnerability is mitigated by the fact that Drupal core's use of
the Archive_Tar library is not vulnerable, as it does not permit
symlinks.

Exploitation may be possible if contrib or custom code uses the
library to extract tar archives (for example .tar, .tar.gz, .bz2, or
.tlz) which come from a potentially untrusted source." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
7.52-2+deb9u16.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u16", rls: "DEB9" ) )){
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

