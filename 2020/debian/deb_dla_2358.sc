if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892358" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2017-12596", "CVE-2017-9110", "CVE-2017-9111", "CVE-2017-9112", "CVE-2017-9113", "CVE-2017-9114", "CVE-2017-9115", "CVE-2017-9116", "CVE-2020-11758", "CVE-2020-11759", "CVE-2020-11760", "CVE-2020-11761", "CVE-2020-11762", "CVE-2020-11763", "CVE-2020-11764", "CVE-2020-11765", "CVE-2020-15305", "CVE-2020-15306" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 22:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-31 03:00:19 +0000 (Mon, 31 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for openexr (DLA-2358-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00056.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2358-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr'
  package(s) announced via the DLA-2358-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were found in the OpenEXR image library, which
could result in denial of service and potentially the execution of
arbitrary code when processing malformed EXR image files." );
	script_tag( name: "affected", value: "'openexr' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.2.0-11+deb9u1.

We recommend that you upgrade your openexr packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenexr-dev", ver: "2.2.0-11+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenexr22", ver: "2.2.0-11+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr", ver: "2.2.0-11+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr-doc", ver: "2.2.0-11+deb9u1", rls: "DEB9" ) )){
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

