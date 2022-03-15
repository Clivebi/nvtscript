if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892368" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-7729" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 00:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-10 07:28:33 +0000 (Thu, 10 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for grunt (DLA-2368-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00008.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2368-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/969668" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'grunt'
  package(s) announced via the DLA-2368-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an arbitrary code execution
vulnerability in grunt, a Javascript task runner. This was possible
due to the unsafe loading of YAML documents." );
	script_tag( name: "affected", value: "'grunt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
1.0.1-5+deb9u1.

We recommend that you upgrade your grunt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "grunt", ver: "1.0.1-5+deb9u1", rls: "DEB9" ) )){
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

