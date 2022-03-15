if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892732" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2021-20299", "CVE-2021-20300", "CVE-2021-20302", "CVE-2021-20303", "CVE-2021-3605" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-01 02:04:00 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-05 03:00:19 +0000 (Thu, 05 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for openexr (DLA-2732-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00008.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2732-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2732-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/990899" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the DLA-2732-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in OpenEXR, a library and
tools for the OpenEXR high dynamic-range (HDR) image format. An
attacker could cause a denial of service (DoS) through application
crash, and possibly execute code." );
	script_tag( name: "affected", value: "'openexr' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.2.0-11+deb9u4.

We recommend that you upgrade your openexr packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenexr-dev", ver: "2.2.0-11+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenexr22", ver: "2.2.0-11+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr", ver: "2.2.0-11+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr-doc", ver: "2.2.0-11+deb9u4", rls: "DEB9" ) )){
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

