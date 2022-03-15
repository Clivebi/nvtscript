if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891913" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-15026" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-26 16:15:00 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "creation_date", value: "2019-09-08 02:00:07 +0000 (Sun, 08 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for memcached (DLA-1913-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00006.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1913-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/939337" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'memcached'
  package(s) announced via the DLA-1913-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a stack-based buffer over-read
in memcached, the in-memory object caching system." );
	script_tag( name: "affected", value: "'memcached' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in memcached version
1.4.21-1.1+deb8u3.

We recommend that you upgrade your memcached packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "memcached", ver: "1.4.21-1.1+deb8u3", rls: "DEB8" ) )){
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

