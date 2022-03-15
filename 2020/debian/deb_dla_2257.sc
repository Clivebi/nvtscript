if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892257" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2016-5735" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-29 03:00:11 +0000 (Mon, 29 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for pngquant (DLA-2257-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2257-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pngquant'
  package(s) announced via the DLA-2257-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that pngquant, a PNG (Portable Network Graphics) image
optimising utility, is susceptible to a buffer overflow write issue
triggered by a maliciously crafted png image, which could lead into
denial of service or other issues." );
	script_tag( name: "affected", value: "'pngquant' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.3.0-1+deb8u1.

We recommend that you upgrade your pngquant packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pngquant", ver: "2.3.0-1+deb8u1", rls: "DEB8" ) )){
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

