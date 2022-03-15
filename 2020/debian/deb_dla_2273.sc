if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892273" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-11989", "CVE-2020-1957" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-17 11:46:23 +0000 (Fri, 17 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for shiro (DLA-2273-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2273-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/955018" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shiro'
  package(s) announced via the DLA-2273-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was two issues in shiro, a security
framework for Java application:

  * CVE-2020-1957: Fix a path-traversal issue where a
specially-crafted request could cause an authentication bypass.

  * CVE-2020-11989: Fix an encoding issue introduced in the handling
of the previous CVE-2020-1957 path-traversal issue which itself
could have also caused an authentication bypass." );
	script_tag( name: "affected", value: "'shiro' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', these issues have been fixed in shiro version
1.3.2-1+deb9u1.

We recommend that you upgrade your shiro packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libshiro-java", ver: "1.3.2-1+deb9u1", rls: "DEB9" ) )){
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

