if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704753" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2019-13290" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 00:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-30 03:00:20 +0000 (Sun, 30 Aug 2020)" );
	script_name( "Debian: Security Advisory for mupdf (DSA-4753-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4753.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4753-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mupdf'
  package(s) announced via the DSA-4753-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A heap-based buffer overflow flaw was discovered in MuPDF, a lightweight
PDF viewer, which may result in denial of service or the execution of
arbitrary code if a malformed PDF file is opened." );
	script_tag( name: "affected", value: "'mupdf' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 1.14.0+ds1-4+deb10u1.

We recommend that you upgrade your mupdf packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmupdf-dev", ver: "1.14.0+ds1-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mupdf", ver: "1.14.0+ds1-4+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mupdf-tools", ver: "1.14.0+ds1-4+deb10u1", rls: "DEB10" ) )){
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

