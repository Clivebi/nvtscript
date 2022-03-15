if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892752" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2021-40153" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-07 19:40:00 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-01 01:00:11 +0000 (Wed, 01 Sep 2021)" );
	script_name( "Debian LTS: Security Advisory for squashfs-tools (DLA-2752-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2752-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2752-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squashfs-tools'
  package(s) announced via the DLA-2752-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in squashfs-tools, a tool to create and append to
squashfs filesystems.
As unsquashfs did not validate all filepaths, it would allow writing
outside of the original destination." );
	script_tag( name: "affected", value: "'squashfs-tools' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1:4.3-3+deb9u2.

We recommend that you upgrade your squashfs-tools packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "squashfs-tools", ver: "1:4.3-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squashfs-tools-dbg", ver: "1:4.3-3+deb9u2", rls: "DEB9" ) )){
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

