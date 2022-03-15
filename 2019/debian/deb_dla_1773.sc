if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891773" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-11627" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-31 18:13:00 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-02 02:00:06 +0000 (Thu, 02 May 2019)" );
	script_name( "Debian LTS: Security Advisory for signing-party (DLA-1773-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1773-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/928256" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'signing-party'
  package(s) announced via the DLA-1773-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An unsafe shell call enabling shell injection via a user ID was
corrected in gpg-key2ps, a tool to generate a PostScript file with
OpenPGP key fingerprint slips." );
	script_tag( name: "affected", value: "'signing-party' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.1.10-3+deb8u1.

We recommend that you upgrade your signing-party packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "signing-party", ver: "1.1.10-3+deb8u1", rls: "DEB8" ) )){
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

