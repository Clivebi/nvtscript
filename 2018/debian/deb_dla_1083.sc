if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891083" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-9110", "CVE-2017-9112", "CVE-2017-9116" );
	script_name( "Debian LTS: Security Advisory for openexr (DLA-1083-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 22:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/08/msg00035.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openexr on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.6.1-6+deb7u1.

We recommend that you upgrade your openexr packages." );
	script_tag( name: "summary", value: "Brandon Perry discovered that openexr, a high dynamic-range (HDR) image
library, was affected by an integer overflow vulnerability and missing
boundary checks that would allow a remote attacker to cause a denial of
service (application crash) via specially crafted image files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenexr-dev", ver: "1.6.1-6+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenexr6", ver: "1.6.1-6+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openexr", ver: "1.6.1-6+deb7u1", rls: "DEB7" ) )){
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

