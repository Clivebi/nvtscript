if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704910" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-22204" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-16 12:15:00 +0000 (Sun, 16 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-03 03:00:04 +0000 (Mon, 03 May 2021)" );
	script_name( "Debian: Security Advisory for libimage-exiftool-perl (DSA-4910-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4910.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4910-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4910-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libimage-exiftool-perl'
  package(s) announced via the DSA-4910-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in libimage-exiftool-perl, a library and
program to read and write meta information in multimedia files, which
may result in execution of arbitrary code if a malformed DjVu file is
processed." );
	script_tag( name: "affected", value: "'libimage-exiftool-perl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 11.16-1+deb10u1.

We recommend that you upgrade your libimage-exiftool-perl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libimage-exiftool-perl", ver: "11.16-1+deb10u1", rls: "DEB10" ) )){
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

