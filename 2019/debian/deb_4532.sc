if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704532" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-16391", "CVE-2019-16392", "CVE-2019-16393", "CVE-2019-16394" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 18:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-09-26 02:00:10 +0000 (Thu, 26 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4532-1 (spip - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4532.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4532-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spip'
  package(s) announced via the DSA-4532-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that SPIP, a website engine for publishing, would
allow unauthenticated users to modify published content and write to
the database, perform cross-site request forgeries, and enumerate
registered users." );
	script_tag( name: "affected", value: "'spip' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 3.1.4-4~deb9u3.

For the stable distribution (buster), these problems have been fixed in
version 3.2.4-1+deb10u1.

We recommend that you upgrade your spip packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "spip", ver: "3.1.4-4~deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "spip", ver: "3.2.4-1+deb10u1", rls: "DEB10" ) )){
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

