if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891846" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-13232" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-16 18:25:00 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "creation_date", value: "2019-07-08 02:00:09 +0000 (Mon, 08 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for unzip (DLA-1846-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1846-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/931433" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unzip'
  package(s) announced via the DLA-1846-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "David Fifield discovered a way to construct non-recursive 'zip bombs'
that achieve a high compression ratio by overlapping files inside the
zip container. However the output size increases quadratically in the
input size, reaching a compression ratio of over 28 million
(10 MB -> 281 TB) at the limits of the zip format which can cause a
denial-of-service. Mark Adler provided a patch to detect and reject
such zip files for the unzip program." );
	script_tag( name: "affected", value: "'unzip' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
6.0-16+deb8u4.

We recommend that you upgrade your unzip packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "unzip", ver: "6.0-16+deb8u4", rls: "DEB8" ) )){
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

