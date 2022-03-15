if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892300" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-15954" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-30 19:24:00 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-31 03:00:12 +0000 (Fri, 31 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for kdepim-runtime (DLA-2300-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/07/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2300-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kdepim-runtime'
  package(s) announced via the DLA-2300-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an issue where kdepim-runtime would
default to using unencrypted POP3 communication despite the UI
indicating that encryption was in use." );
	script_tag( name: "affected", value: "'kdepim-runtime' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this issue has been fixed in kdepim-runtime version
4:16.04.2-2+deb9u1.

We recommend that you upgrade your kdepim-runtime packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "kdepim-runtime", ver: "4:16.04.2-2+deb9u1", rls: "DEB9" ) )){
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

