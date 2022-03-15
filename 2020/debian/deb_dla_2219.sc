if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892219" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2017-7875" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-24 20:15:00 +0000 (Sun, 24 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-25 03:00:06 +0000 (Mon, 25 May 2020)" );
	script_name( "Debian LTS: Security Advisory for feh (DLA-2219-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2219-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'feh'
  package(s) announced via the DLA-2219-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Tobias Stoeckmann discovered that it was possible to trigger an
out-of-boundary heap write with the image viewer feh while receiving
an IPC message." );
	script_tag( name: "affected", value: "'feh' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.12-1+deb8u1.

We recommend that you upgrade your feh packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "feh", ver: "2.12-1+deb8u1", rls: "DEB8" ) )){
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

