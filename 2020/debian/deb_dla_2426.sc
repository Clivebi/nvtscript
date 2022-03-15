if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892426" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-15250" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-14 23:15:00 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:00:20 +0000 (Tue, 03 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for junit4 (DLA-2426-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2426-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/972231" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'junit4'
  package(s) announced via the DLA-2426-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In junit4 the test rule TemporaryFolder contains a local information
disclosure vulnerability. On Unix like systems, the system's temporary
directory is shared between all users on that system. Because of this,
when files and directories are written into this directory they are, by
default, readable by other users on that same system. This vulnerability
does not allow other users to overwrite the contents of these directories
or files. This is purely an information disclosure vulnerability. This
vulnerability impacts you if the JUnit tests write sensitive information,
like API keys or passwords, into the temporary folder, and the JUnit
tests execute in an environment where the OS has other untrusted users." );
	script_tag( name: "affected", value: "'junit4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
4.12-4+deb9u1.

We recommend that you upgrade your junit4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "junit4", ver: "4.12-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "junit4-doc", ver: "4.12-4+deb9u1", rls: "DEB9" ) )){
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

