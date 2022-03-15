if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892503" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-7788" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-23 15:42:00 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-22 04:00:10 +0000 (Tue, 22 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for node-ini (DLA-2503-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00032.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2503-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/977718" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'node-ini'
  package(s) announced via the DLA-2503-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an issue in node-ini, a .ini format
parser and serializer for Node.js, where an application could be
exploited by a malicious input file." );
	script_tag( name: "affected", value: "'node-ini' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
1.1.0-1+deb9u1.

We recommend that you upgrade your node-ini packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "node-ini", ver: "1.1.0-1+deb9u1", rls: "DEB9" ) )){
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

