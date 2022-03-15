if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892000" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-16729" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 20:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:50:08 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for pam-python (DLA-2000-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2000-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942514" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pam-python'
  package(s) announced via the DLA-2000-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that pam-python, a PAM Module that runs the Python
interpreter, has an issue in regard to the default environment variable
handling of Python. This issue could allow for local root escalation in certain
PAM setups." );
	script_tag( name: "affected", value: "'pam-python' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.0.4-1.1+deb8u1.

We recommend that you upgrade your pam-python packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpam-python", ver: "1.0.4-1.1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-python-doc", ver: "1.0.4-1.1+deb8u1", rls: "DEB8" ) )){
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

