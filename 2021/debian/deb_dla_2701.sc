if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892701" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2020-16587", "CVE-2021-20296", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476", "CVE-2021-3477", "CVE-2021-3478", "CVE-2021-3479", "CVE-2021-3598" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-11 04:15:00 +0000 (Sun, 11 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-04 03:00:18 +0000 (Sun, 04 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for openexr (DLA-2701-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2701-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2701-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/986796" );
	script_xref( name: "URL", value: "https://bugs.debian.org/990450" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the DLA-2701-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in OpenEXR, a library and
tools for the OpenEXR high dynamic-range (HDR) image format. An
attacker could cause a denial of service (DoS) through application
crash and excessive memory consumption." );
	script_tag( name: "affected", value: "'openexr' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.2.0-11+deb9u3.

We recommend that you upgrade your openexr packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenexr-dev", ver: "2.2.0-11+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenexr22", ver: "2.2.0-11+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr", ver: "2.2.0-11+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr-doc", ver: "2.2.0-11+deb9u3", rls: "DEB9" ) )){
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

