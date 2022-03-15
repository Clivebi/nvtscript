if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892249" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-0182", "CVE-2020-0198" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-06 16:01:00 +0000 (Mon, 06 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-14 03:00:24 +0000 (Sun, 14 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for libexif (DLA-2249-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2249-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/962345" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libexif'
  package(s) announced via the DLA-2249-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following CVE(s) were reported against src:libexif.

CVE-2020-0182

In exif_entry_get_value of exif-entry.c, there is a possible
out of bounds read due to a missing bounds check. This could
lead to local information disclosure with no additional execution
privileges needed. User interaction is not needed for
exploitation.

CVE-2020-0198

In exif_data_load_data_content of exif-data.c, there is a
possible UBSAN abort due to an integer overflow. This could lead
to remote denial of service with no additional execution
privileges needed. User interaction is needed for exploitation." );
	script_tag( name: "affected", value: "'libexif' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.6.21-2+deb8u4.

We recommend that you upgrade your libexif packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libexif-dev", ver: "0.6.21-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexif12", ver: "0.6.21-2+deb8u4", rls: "DEB8" ) )){
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

