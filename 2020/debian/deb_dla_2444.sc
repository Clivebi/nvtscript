if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892444" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-8037" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 13:12:00 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2020-11-11 04:00:24 +0000 (Wed, 11 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for tcpdump (DLA-2444-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2444-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/973877" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tcpdump'
  package(s) announced via the DLA-2444-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The ppp de-capsulator in tcpdump 4.9.3 can be convinced to allocate
a large amount of memory.

The buffer should be big enough to hold the captured data, but it
doesn't need to be big enough to hold the entire on-the-network
packet, if we haven't captured all of it." );
	script_tag( name: "affected", value: "'tcpdump' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
4.9.3-1~deb9u2.

We recommend that you upgrade your tcpdump packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tcpdump", ver: "4.9.3-1~deb9u2", rls: "DEB9" ) )){
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
