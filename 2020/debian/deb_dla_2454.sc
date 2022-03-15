if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892454" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2019-11840" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-18 00:15:00 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-11-19 04:00:08 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for rclone (DLA-2454-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2454-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rclone'
  package(s) announced via the DLA-2454-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "golang-go.crypto was recently updated with a fix for CVE-2019-11840. This in
turn requires all packages that use the affected code to be recompiled in order
to pick up the security fix.

CVE-2019-11840

An issue was discovered in supplementary Go cryptography libraries, aka
golang-googlecode-go-crypto. If more than 256 GiB of keystream is
generated, or if the counter otherwise grows greater than 32 bits, the amd64
implementation will first generate incorrect output, and then cycle back to
previously generated keystream. Repeated keystream bytes can lead to loss of
confidentiality in encryption applications, or to predictability in CSPRNG
applications." );
	script_tag( name: "affected", value: "'rclone' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.35-1+deb8u1.

We recommend that you upgrade your rclone packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-github-ncw-rclone-dev", ver: "1.35-1+deb8u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "rclone", ver: "1.35-1+deb8u1", rls: "DEB9" ) )){
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

