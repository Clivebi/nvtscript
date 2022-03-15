if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704765" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2020-15598" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 03:16:00 +0000 (Wed, 14 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-20 03:00:05 +0000 (Sun, 20 Sep 2020)" );
	script_name( "Debian: Security Advisory for modsecurity (DSA-4765-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4765.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4765-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'modsecurity'
  package(s) announced via the DSA-4765-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ervin Hegedues discovered that ModSecurity v3 enabled global regular
expression matching which could result in denial of service. For
additional information please refer to the references." );
	script_tag( name: "affected", value: "'modsecurity' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 3.0.3-1+deb10u2.

We recommend that you upgrade your modsecurity packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://coreruleset.org/20200914/cve-2020-15598/" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmodsecurity-dev", ver: "3.0.3-1+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmodsecurity3", ver: "3.0.3-1+deb10u2", rls: "DEB10" ) )){
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

