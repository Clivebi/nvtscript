if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892562" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-27229" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-19 04:00:19 +0000 (Fri, 19 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for mumble (DLA-2562-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2562-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2562-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/982904" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mumble'
  package(s) announced via the DLA-2562-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a remote code execution
vulnerability in mumble, a VoIP client commonly used for group chats.
The exploit could have been been triggered by a maliciously crafted
URL on the server list." );
	script_tag( name: "affected", value: "'mumble' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
1.2.18-1+deb9u2.

We recommend that you upgrade your mumble packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mumble", ver: "1.2.18-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mumble-dbg", ver: "1.2.18-1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mumble-server", ver: "1.2.18-1+deb9u2", rls: "DEB9" ) )){
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

