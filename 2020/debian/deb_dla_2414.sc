if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892414" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-27638" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-03 03:15:00 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-26 04:00:24 +0000 (Mon, 26 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for fastd (DLA-2414-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2414-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/972521" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fastd'
  package(s) announced via the DLA-2414-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In fastd, a fast and secure tunnelling daemon, a receive buffer
handling problem was discovered which allows a denial of service
(memory exhaustion) when receiving packets with an invalid type code." );
	script_tag( name: "affected", value: "'fastd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
18-2+deb9u1.

We recommend that you upgrade your fastd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "fastd", ver: "18-2+deb9u1", rls: "DEB9" ) )){
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

