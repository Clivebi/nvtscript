if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704555" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-16729" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 20:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-10-31 03:00:38 +0000 (Thu, 31 Oct 2019)" );
	script_name( "Debian Security Advisory DSA 4555-1 (pam-python - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4555.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4555-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam-python'
  package(s) announced via the DSA-4555-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Malte Kraus discovered that libpam-python, a PAM module allowing PAM
modules to be written in Python, didn't sanitise environment variables
which could result in local privilege escalation if used with a
setuid binary." );
	script_tag( name: "affected", value: "'pam-python' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 1.0.6-1.1+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.0.6-1.1+deb10u1.

We recommend that you upgrade your pam-python packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpam-python", ver: "1.0.6-1.1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-python-doc", ver: "1.0.6-1.1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-python", ver: "1.0.6-1.1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-python-doc", ver: "1.0.6-1.1+deb9u1", rls: "DEB9" ) )){
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

