if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891909" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2015-9381", "CVE-2015-9382", "CVE-2015-9383" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-10 03:15:00 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-05 02:00:12 +0000 (Thu, 05 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for freetype (DLA-1909-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1909-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freetype'
  package(s) announced via the DLA-1909-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several newly-referenced issues have been fixed in the FreeType 2 font
engine.

CVE-2015-9381

heap-based buffer over-read in T1_Get_Private_Dict in
type1/t1parse.c

CVE-2015-9382

buffer over-read in skip_comment in psaux/psobjs.c because
ps_parser_skip_PS_token is mishandled in an FT_New_Memory_Face
operation

CVE-2015-9383

a heap-based buffer over-read in tt_cmap14_validate in
sfnt/ttcmap.c" );
	script_tag( name: "affected", value: "'freetype' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.5.2-3+deb8u4.

We recommend that you upgrade your freetype packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "freetype2-demos", ver: "2.5.2-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.5.2-3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreetype6-dev", ver: "2.5.2-3+deb8u4", rls: "DEB8" ) )){
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

