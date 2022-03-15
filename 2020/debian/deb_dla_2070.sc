if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892070" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2019-16779" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-14 01:15:00 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-20 04:00:07 +0000 (Mon, 20 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for ruby-excon (DLA-2070-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2070-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/946904" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-excon'
  package(s) announced via the DLA-2070-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In RubyGem excon before 0.71.0, there was a race condition around
persistent connections, where a connection which is interrupted (such
as by a timeout) would leave data on the socket. Subsequent requests
would then read this data, returning content from the previous response." );
	script_tag( name: "affected", value: "'ruby-excon' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.33.0-2+deb8u1.

We recommend that you upgrade your ruby-excon packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-excon", ver: "0.33.0-2+deb8u1", rls: "DEB8" ) )){
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

