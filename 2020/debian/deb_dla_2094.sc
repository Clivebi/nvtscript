if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892094" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2019-18634" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-07 17:15:00 +0000 (Fri, 07 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-02 04:00:08 +0000 (Sun, 02 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for sudo (DLA-2094-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2094-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the DLA-2094-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A stack-based buffer overflow vulnerability in sudo, a program designed
to provide limited super user privileges to specific users, triggerable
when configured with the pwfeedback option enabled. An unprivileged user
can take advantage of this flaw to obtain full root privileges." );
	script_tag( name: "affected", value: "'sudo' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.8.10p3-1+deb8u7.

We recommend that you upgrade your sudo packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sudo", ver: "1.8.10p3-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.8.10p3-1+deb8u7", rls: "DEB8" ) )){
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

