if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891965" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-3689" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-25 18:51:00 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-10-20 02:00:07 +0000 (Sun, 20 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for nfs-utils (DLA-1965-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1965-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/940848" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nfs-utils'
  package(s) announced via the DLA-1965-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In the nfs-utils package, providing support files for Network File
System (NFS) including the rpc.statd daemon, the directory
/var/lib/nfs is owned by statd:nogroup. This directory contains files
owned and managed by root. If statd is compromised, it can therefore
trick processes running with root privileges into creating/overwriting
files anywhere on the system." );
	script_tag( name: "affected", value: "'nfs-utils' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.2.8-9+deb8u1.

We recommend that you upgrade your nfs-utils packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "nfs-common", ver: "1:1.2.8-9+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "nfs-kernel-server", ver: "1:1.2.8-9+deb8u1", rls: "DEB8" ) )){
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

