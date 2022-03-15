if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892746" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_cve_id( "CVE-2021-29376" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-02 15:50:00 +0000 (Fri, 02 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-08-21 03:00:09 +0000 (Sat, 21 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for scrollz (DLA-2746-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2746-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2746-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'scrollz'
  package(s) announced via the DLA-2746-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in scrollz, an advanced ircII-based IRC client.
A crafted CTCP UTC message could allow an attacker to disconnect the
victim from an IRC server due to a segmentation fault and client crash." );
	script_tag( name: "affected", value: "'scrollz' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2.2.3-1+deb9u1.

We recommend that you upgrade your scrollz packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "scrollz", ver: "2.2.3-1+deb9u1", rls: "DEB9" ) )){
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

